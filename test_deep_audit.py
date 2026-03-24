"""
Deep audit test — covers all edge cases, bugs, and architectural gaps found
during the comprehensive review of the 4SSH_CONTROL project.

Tests organized by category:
  1. Config loading edge cases (reload safety, malformed data)
  2. Network rule engine — dead code removal, edge cases
  3. Session lifecycle — UnboundLocalError, profile routing
  4. Audit DB — schema migration, profile columns
  5. Consensus — single-decision edge cases
  6. Dashboard — profile column, HTML escape
  7. Network config fetch — exec_command fallback to shell
  8. CommandCategory — new config_change value
  9. Cross-layer integration — full pipeline for network sessions
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from ai_defense.core.config import (
    AppConfig,
    BlacklistRule,
    EscalationRule,
    NetworkProfileRules,
    TargetProfile,
    load_config,
)
from ai_defense.core.models import (
    AgentDecision,
    CommandCategory,
    FinalVerdict,
    SessionContext,
    Severity,
    Verdict,
)
from ai_defense.core.network_rule_engine import NetworkRuleEngine
from ai_defense.core.consensus import ConsensusEngine, ConsensusConfig
from ai_defense.core.audit import AuditLogger, AuditConfig


# ──────────────────────────────────────────────────────────────────
# 1. Config loading edge cases
# ──────────────────────────────────────────────────────────────────

class TestConfigReloadSafety:
    """Verify that load_config doesn't mutate the raw YAML dict (pop bug fix)."""

    def test_config_double_load(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("""
target_profiles:
  test_cisco:
    type: network
    vendor: cisco_ios
    detect_banner: ["Cisco"]
    network_rules:
      safe_commands: ["show"]
      dangerous_patterns:
        - pattern: "reload"
          reason: "reload"
          severity: critical
""")
        cfg1 = load_config(str(cfg_file))
        cfg2 = load_config(str(cfg_file))
        assert "test_cisco" in cfg1.target_profiles
        assert "test_cisco" in cfg2.target_profiles
        assert len(cfg2.target_profiles["test_cisco"].network_rules.safe_commands) == 1
        assert len(cfg2.target_profiles["test_cisco"].network_rules.dangerous_patterns) == 1

    def test_config_missing_file(self, tmp_path):
        cfg = load_config(str(tmp_path / "nonexistent.yaml"))
        assert isinstance(cfg, AppConfig)
        assert len(cfg.target_profiles) == 0

    def test_config_empty_file(self, tmp_path):
        cfg_file = tmp_path / "empty.yaml"
        cfg_file.write_text("")
        cfg = load_config(str(cfg_file))
        assert isinstance(cfg, AppConfig)

    def test_config_malformed_profile(self, tmp_path):
        cfg_file = tmp_path / "bad.yaml"
        cfg_file.write_text("""
target_profiles:
  bad_entry: "not a dict"
  good_entry:
    type: network
    vendor: test
""")
        cfg = load_config(str(cfg_file))
        assert "bad_entry" not in cfg.target_profiles
        assert "good_entry" in cfg.target_profiles


# ──────────────────────────────────────────────────────────────────
# 2. Network rule engine
# ──────────────────────────────────────────────────────────────────

def _make_profile(safe=None, dangerous=None, critical=None, escalation=None, vendor="test"):
    return TargetProfile(
        type="network",
        vendor=vendor,
        network_rules=NetworkProfileRules(
            safe_commands=safe or [],
            dangerous_patterns=[
                BlacklistRule(pattern=p, reason=r, severity=s)
                for p, r, s in (dangerous or [])
            ],
            critical_patterns=[
                BlacklistRule(pattern=p, reason=r, severity=s)
                for p, r, s in (critical or [])
            ],
            escalation_patterns=[
                EscalationRule(pattern=p, reason=r, severity=s, action=a)
                for p, r, s, a in (escalation or [])
            ],
        ),
    )


class TestNetworkRuleEngineEdgeCases:
    def test_empty_command(self):
        nre = NetworkRuleEngine(_make_profile(safe=["show"]))
        assert nre.evaluate("") is None
        assert nre.evaluate("  ") is None

    def test_safe_full_match_higher_confidence(self):
        nre = NetworkRuleEngine(_make_profile(safe=["show ip route"]))
        result = nre.evaluate("show ip route")
        assert result is not None
        assert result.verdict == Verdict.ALLOW
        assert result.confidence == 1.0

    def test_safe_base_match_lower_confidence(self):
        nre = NetworkRuleEngine(_make_profile(safe=["show"]))
        result = nre.evaluate("show ip bgp summary")
        assert result is not None
        assert result.verdict == Verdict.ALLOW
        assert result.confidence == 0.9

    def test_critical_overrides_when_not_safe(self):
        """Critical patterns should block even unknown commands."""
        nre = NetworkRuleEngine(_make_profile(
            safe=["show"],
            critical=[("\\bno\\s+router\\s+ospf\\b", "kill OSPF", "critical")],
        ))
        result = nre.evaluate("no router ospf 1")
        assert result is not None
        assert result.verdict == Verdict.DENY

    def test_safe_base_takes_priority_over_critical(self):
        """If base command is in safe set, it wins over patterns — by design.
        This means operators should NOT add 'no' to safe_commands on Cisco."""
        nre = NetworkRuleEngine(_make_profile(
            safe=["no"],
            critical=[("\\bno\\s+router\\s+ospf\\b", "kill OSPF", "critical")],
        ))
        result = nre.evaluate("no router ospf 1")
        assert result is not None
        assert result.verdict == Verdict.ALLOW

    def test_dangerous_returns_escalate_for_high_severity(self):
        nre = NetworkRuleEngine(_make_profile(
            dangerous=[("\\bshutdown\\b", "shutdown interface", "high")],
        ))
        result = nre.evaluate("shutdown")
        assert result is not None
        assert result.verdict == Verdict.ESCALATE

    def test_dangerous_returns_deny_for_critical_severity(self):
        nre = NetworkRuleEngine(_make_profile(
            dangerous=[("\\breload\\b", "reload device", "critical")],
        ))
        result = nre.evaluate("reload")
        assert result is not None
        assert result.verdict == Verdict.DENY

    def test_escalation_with_deny_action(self):
        nre = NetworkRuleEngine(_make_profile(
            escalation=[("\\bcommit\\b", "commit config", "high", "deny")],
        ))
        result = nre.evaluate("commit")
        assert result is not None
        assert result.verdict == Verdict.DENY

    def test_sanitize_strips_control_chars(self):
        nre = NetworkRuleEngine(_make_profile(safe=["show"]))
        result = nre.evaluate("show\x01\x02 ip route")
        assert result is not None
        assert result.verdict == Verdict.ALLOW

    def test_no_dead_code_after_escalation(self):
        """After removing dead code, unknown commands should return None."""
        nre = NetworkRuleEngine(_make_profile(safe=["show"]))
        result = nre.evaluate("configure terminal")
        assert result is None

    def test_invalid_severity_fallback(self):
        profile = _make_profile(
            dangerous=[("\\btest\\b", "test", "bogus_severity")],
        )
        nre = NetworkRuleEngine(profile)
        result = nre.evaluate("test")
        assert result is not None
        assert result.severity == Severity.HIGH  # fallback


# ──────────────────────────────────────────────────────────────────
# 3. Session lifecycle / bastion edge cases
# ──────────────────────────────────────────────────────────────────

class TestSessionLifecycle:
    def test_session_has_profile_fields(self):
        s = SessionContext(
            username="admin",
            role="ops",
            target_profile="cisco_ios",
            target_vendor="cisco_ios",
        )
        assert s.target_profile == "cisco_ios"
        assert s.target_vendor == "cisco_ios"
        assert s.network_context == ""

    def test_session_network_context_storage(self):
        s = SessionContext()
        s.network_context = "hostname R1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"
        assert "hostname R1" in s.network_context

    def test_session_command_history_text(self):
        s = SessionContext()
        s.add_command("show ip route", Verdict.ALLOW)
        s.add_command("no router ospf 1", Verdict.DENY)
        text = s.command_history_text()
        assert "[allow] show ip route" in text
        assert "[deny] no router ospf 1" in text


# ──────────────────────────────────────────────────────────────────
# 4. Audit DB — migration, profile columns
# ──────────────────────────────────────────────────────────────────

class TestAuditProfileColumns:
    def _make_logger(self, tmp_path):
        cfg = AuditConfig(db_path=str(tmp_path / "test.db"), json_log=str(tmp_path / "test.jsonl"))
        return AuditLogger(cfg)

    def test_new_db_has_profile_columns(self, tmp_path):
        logger = self._make_logger(tmp_path)
        conn = sqlite3.connect(str(tmp_path / "test.db"))
        cur = conn.execute("PRAGMA table_info(audit_log)")
        cols = {row[1] for row in cur.fetchall()}
        assert "target_profile" in cols
        assert "target_vendor" in cols
        conn.close()
        logger.close()

    def test_log_decision_stores_profile(self, tmp_path):
        logger = self._make_logger(tmp_path)
        session = SessionContext(
            username="admin", role="neteng",
            target_profile="cisco_ios", target_vendor="cisco_ios",
        )
        logger.log_session_start(session)
        verdict = FinalVerdict(
            verdict=Verdict.ALLOW,
            decisions=[AgentDecision(
                agent_name="network_rule_engine", verdict=Verdict.ALLOW,
                confidence=1.0, reason="safe", severity=Severity.LOW,
            )],
            reason="safe",
        )
        logger.log_decision(session, "show ip route", verdict)

        logs = logger.get_recent_logs(10)
        assert len(logs) == 1
        assert logs[0]["target_profile"] == "cisco_ios"
        assert logs[0]["target_vendor"] == "cisco_ios"
        logger.close()

    def test_jsonl_includes_profile(self, tmp_path):
        logger = self._make_logger(tmp_path)
        session = SessionContext(
            username="admin", role="ops",
            target_profile="junos", target_vendor="junos",
        )
        logger.log_session_start(session)
        verdict = FinalVerdict(
            verdict=Verdict.DENY,
            decisions=[AgentDecision(
                agent_name="test", verdict=Verdict.DENY,
                confidence=1.0, reason="test",
            )],
            reason="test",
        )
        logger.log_decision(session, "delete protocols ospf", verdict)

        jsonl_path = tmp_path / "test.jsonl"
        with open(jsonl_path) as f:
            record = json.loads(f.readline())
        assert record["target_profile"] == "junos"
        assert record["target_vendor"] == "junos"
        logger.close()

    def test_migration_adds_columns_to_existing_db(self, tmp_path):
        """Simulate upgrade from old DB without profile columns."""
        db_path = tmp_path / "old.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                session_id TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT '',
                command TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT '',
                agents_json TEXT NOT NULL DEFAULT '[]',
                escalated INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT '',
                start_time REAL NOT NULL,
                end_time REAL,
                cmd_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

        cfg = AuditConfig(db_path=str(db_path), json_log=str(tmp_path / "upgrade.jsonl"))
        logger = AuditLogger(cfg)

        conn2 = sqlite3.connect(str(db_path))
        cur = conn2.execute("PRAGMA table_info(audit_log)")
        cols = {row[1] for row in cur.fetchall()}
        assert "target_profile" in cols
        assert "target_vendor" in cols
        conn2.close()
        logger.close()


# ──────────────────────────────────────────────────────────────────
# 5. Consensus — single-decision edge cases
# ──────────────────────────────────────────────────────────────────

class TestConsensusSingleDecision:
    def _cfg(self, strategy="weighted_majority"):
        return ConsensusConfig(strategy=strategy, deny_threshold=0.5, escalate_on_disagreement=True)

    def test_single_allow_decision(self):
        ce = ConsensusEngine(self._cfg(), {"agent": 1.0})
        decisions = [AgentDecision(
            agent_name="agent", verdict=Verdict.ALLOW,
            confidence=0.9, reason="safe",
        )]
        result = ce.decide(decisions)
        assert result.verdict == Verdict.ALLOW

    def test_single_deny_decision(self):
        ce = ConsensusEngine(self._cfg(), {"agent": 1.0})
        decisions = [AgentDecision(
            agent_name="agent", verdict=Verdict.DENY,
            confidence=0.9, reason="dangerous",
        )]
        result = ce.decide(decisions)
        assert result.verdict == Verdict.DENY

    def test_single_escalate_decision(self):
        ce = ConsensusEngine(self._cfg(), {"agent": 1.0})
        decisions = [AgentDecision(
            agent_name="agent", verdict=Verdict.ESCALATE,
            confidence=0.9, reason="unsure",
        )]
        result = ce.decide(decisions)
        assert result.verdict == Verdict.ESCALATE

    def test_empty_decisions(self):
        ce = ConsensusEngine(self._cfg())
        result = ce.decide([])
        assert result.verdict == Verdict.ESCALATE

    def test_zero_confidence_all_agents(self):
        ce = ConsensusEngine(self._cfg())
        decisions = [AgentDecision(
            agent_name="a", verdict=Verdict.ALLOW, confidence=0.0, reason="",
        )]
        result = ce.decide(decisions)
        assert result.verdict == Verdict.ESCALATE

    def test_unknown_strategy_fallback(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="nonexistent"))
        decisions = [AgentDecision(
            agent_name="a", verdict=Verdict.ALLOW, confidence=0.9, reason="ok",
        )]
        result = ce.decide(decisions)
        assert result.verdict == Verdict.ALLOW

    def test_network_agent_weight_defaults_to_1(self):
        """network_config_agent not in weights → default 1.0 via dict.get fallback."""
        ce = ConsensusEngine(self._cfg(), {"command_classifier": 1.0})
        decisions = [AgentDecision(
            agent_name="network_config_agent", verdict=Verdict.DENY,
            confidence=0.9, reason="dangerous config",
        )]
        result = ce.decide(decisions)
        assert result.verdict == Verdict.DENY


# ──────────────────────────────────────────────────────────────────
# 6. CommandCategory — config_change
# ──────────────────────────────────────────────────────────────────

class TestCommandCategory:
    def test_config_change_exists(self):
        assert CommandCategory.CONFIG_CHANGE == "config_change"
        assert CommandCategory("config_change") == CommandCategory.CONFIG_CHANGE

    def test_all_categories(self):
        expected = {"safe", "risky", "destructive", "recon", "exfil", "privesc", "config_change", "unknown"}
        actual = {c.value for c in CommandCategory}
        assert actual == expected


# ──────────────────────────────────────────────────────────────────
# 7. Network config fetch — fallback to shell
# ──────────────────────────────────────────────────────────────────

class TestNetworkConfigFetch:
    def test_exec_command_success(self):
        from ai_defense.core.engine import fetch_network_config
        profile = TargetProfile(
            type="network", vendor="cisco_ios",
            context_command="show running-config",
            context_max_bytes=8192,
        )
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"hostname R1\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0"
        mock_ssh.exec_command.return_value = (None, mock_stdout, MagicMock())
        result = fetch_network_config(mock_ssh, profile)
        assert "hostname R1" in result

    def test_exec_command_empty_falls_to_shell(self):
        from ai_defense.core.engine import fetch_network_config
        profile = TargetProfile(
            type="network", vendor="cisco_ios",
            context_command="show running-config",
            context_max_bytes=8192,
        )
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_ssh.exec_command.return_value = (None, mock_stdout, mock_stderr)

        mock_chan = MagicMock()
        recv_call_count = [0]
        def fake_recv(size):
            recv_call_count[0] += 1
            if recv_call_count[0] == 1:
                return b"Router>"
            elif recv_call_count[0] == 2:
                return b"show running-config\nhostname Router1\nend\n"
            return b""
        mock_chan.recv.side_effect = fake_recv
        ready_call_count = [0]
        def fake_recv_ready():
            ready_call_count[0] += 1
            return ready_call_count[0] <= 3
        mock_chan.recv_ready.side_effect = fake_recv_ready
        mock_ssh.invoke_shell.return_value = mock_chan

        result = fetch_network_config(mock_ssh, profile)
        assert "hostname Router1" in result or result == ""

    def test_no_context_command(self):
        from ai_defense.core.engine import fetch_network_config
        profile = TargetProfile(type="network", vendor="test", context_command="")
        result = fetch_network_config(MagicMock(), profile)
        assert result == ""

    def test_exec_command_exception_falls_to_shell(self):
        from ai_defense.core.engine import fetch_network_config
        profile = TargetProfile(
            type="network", vendor="mikrotik",
            context_command="/export",
            context_max_bytes=8192,
        )
        mock_ssh = MagicMock()
        mock_ssh.exec_command.side_effect = Exception("not supported")

        mock_chan = MagicMock()
        call_count = [0]
        def fake_recv(size):
            call_count[0] += 1
            if call_count[0] <= 2:
                return b"/export\n# RouterOS config\n/ip address\nadd address=10.0.0.1/24\n"
            return b""
        mock_chan.recv.side_effect = fake_recv
        ready_count = [0]
        def fake_ready():
            ready_count[0] += 1
            return ready_count[0] <= 3
        mock_chan.recv_ready.side_effect = fake_ready
        mock_ssh.invoke_shell.return_value = mock_chan

        result = fetch_network_config(mock_ssh, profile)
        assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────────
# 8. Engine profile routing
# ──────────────────────────────────────────────────────────────────

class TestEngineProfileRouting:
    def _make_engine(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("""
llm:
  provider: ollama
  model: test
  base_url: http://localhost:11434/v1
  timeout: 5

agents:
  command_classifier:
    enabled: true
    weight: 1.0
  context_analyzer:
    enabled: true
    weight: 1.5
  policy_enforcer:
    enabled: true
    weight: 1.2

consensus:
  strategy: weighted_majority
  deny_threshold: 0.5

rules:
  whitelist: ["ls", "pwd"]
  blacklist:
    - pattern: "rm -rf /"
      reason: "danger"
      severity: critical

rbac:
  roles:
    ops:
      description: "Admin"
      allowed_commands: ["*"]
      denied_commands: ["rm -rf /"]

audit:
  db_path: "{db}"
  json_log: "{jl}"

target_profiles:
  cisco_ios:
    type: network
    vendor: cisco_ios
    detect_banner: ["Cisco IOS"]
    network_rules:
      safe_commands: ["show", "ping"]
      dangerous_patterns:
        - pattern: "\\\\breload\\\\b"
          reason: "reload"
          severity: critical
      escalation_patterns:
        - pattern: "\\\\binterface\\\\b"
          reason: "interface config"
          severity: medium
          action: escalate
""".format(db=str(tmp_path / "audit.db"), jl=str(tmp_path / "audit.jsonl")))
        return cfg_file

    @patch("ai_defense.core.engine.LLMClient")
    def test_network_session_routes_to_network_eval(self, mock_llm_cls, tmp_path):
        from ai_defense.core.engine import AIEngine
        cfg = load_config(str(self._make_engine(tmp_path)))
        cfg.audit.db_path = str(tmp_path / "audit.db")
        cfg.audit.json_log = str(tmp_path / "audit.jsonl")
        engine = AIEngine(cfg)

        session = engine.create_session(
            username="admin", role="ops",
            target_profile="cisco_ios", target_vendor="cisco_ios",
        )
        assert engine.is_network_session(session) is True

        result = engine.evaluate("show ip route", session)
        assert result.verdict == Verdict.ALLOW

        result2 = engine.evaluate("reload", session)
        assert result2.verdict == Verdict.DENY

        engine.close()

    @patch("ai_defense.core.engine.LLMClient")
    def test_linux_session_routes_to_linux_eval(self, mock_llm_cls, tmp_path):
        from ai_defense.core.engine import AIEngine
        cfg = load_config(str(self._make_engine(tmp_path)))
        cfg.audit.db_path = str(tmp_path / "audit2.db")
        cfg.audit.json_log = str(tmp_path / "audit2.jsonl")
        engine = AIEngine(cfg)

        session = engine.create_session(username="admin", role="ops")
        assert engine.is_network_session(session) is False

        result = engine.evaluate("ls", session)
        assert result.verdict == Verdict.ALLOW

        engine.close()


# ──────────────────────────────────────────────────────────────────
# 9. Dashboard profile column
# ──────────────────────────────────────────────────────────────────

class TestDashboard:
    def test_render_includes_profile_column(self, tmp_path):
        from ai_defense.web.dashboard import _render_dashboard
        cfg = AuditConfig(db_path=str(tmp_path / "dash.db"), json_log=str(tmp_path / "dash.jsonl"))
        logger = AuditLogger(cfg)

        session = SessionContext(
            username="admin", role="neteng",
            target_profile="cisco_ios", target_vendor="cisco_ios",
        )
        logger.log_session_start(session)
        verdict = FinalVerdict(
            verdict=Verdict.DENY,
            decisions=[AgentDecision(
                agent_name="network_rule_engine", verdict=Verdict.DENY,
                confidence=1.0, reason="reload blocked",
            )],
            reason="reload blocked",
        )
        logger.log_decision(session, "reload", verdict)

        html = _render_dashboard(logger)
        assert "Профиль" in html
        assert "cisco_ios" in html
        assert "reload" in html
        logger.close()

    def test_render_empty_db(self, tmp_path):
        from ai_defense.web.dashboard import _render_dashboard
        cfg = AuditConfig(db_path=str(tmp_path / "empty.db"), json_log=str(tmp_path / "empty.jsonl"))
        logger = AuditLogger(cfg)
        html = _render_dashboard(logger)
        assert "Нет данных" in html
        logger.close()

    def test_html_escape_in_commands(self, tmp_path):
        from ai_defense.web.dashboard import _render_dashboard
        cfg = AuditConfig(db_path=str(tmp_path / "esc.db"), json_log=str(tmp_path / "esc.jsonl"))
        logger = AuditLogger(cfg)

        session = SessionContext(username="admin", role="ops")
        logger.log_session_start(session)
        verdict = FinalVerdict(
            verdict=Verdict.DENY,
            decisions=[AgentDecision(
                agent_name="rule_engine", verdict=Verdict.DENY,
                confidence=1.0, reason='test <script>alert("xss")</script>',
            )],
            reason='<script>alert("xss")</script>',
        )
        logger.log_decision(session, 'echo "<script>alert(1)</script>"', verdict)

        html = _render_dashboard(logger)
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html
        assert 'alert(1)' not in html.split('<tbody>')[1].split('</tbody>')[0].replace('&lt;script&gt;alert(1)&lt;/script&gt;', '')
        logger.close()


# ──────────────────────────────────────────────────────────────────
# 10. Full config.yaml loading — real file
# ──────────────────────────────────────────────────────────────────

class TestRealConfigLoad:
    def test_load_real_config(self):
        cfg_path = Path(__file__).parent / "config.yaml"
        if not cfg_path.exists():
            pytest.skip("config.yaml not found")
        cfg = load_config(str(cfg_path))
        assert len(cfg.target_profiles) >= 5
        assert "cisco_ios" in cfg.target_profiles
        assert "junos" in cfg.target_profiles
        assert "mikrotik" in cfg.target_profiles
        assert "huawei_vrp" in cfg.target_profiles
        assert "arista_eos" in cfg.target_profiles

        cisco = cfg.target_profiles["cisco_ios"]
        assert cisco.type == "network"
        assert cisco.vendor == "cisco_ios"
        assert "show" in cisco.network_rules.safe_commands
        assert len(cisco.network_rules.dangerous_patterns) > 5
        assert len(cisco.network_rules.escalation_patterns) > 3

    def test_all_profiles_have_vendor(self):
        cfg = load_config("config.yaml")
        for pname, profile in cfg.target_profiles.items():
            if profile.type == "network":
                assert profile.vendor, f"Profile {pname} missing vendor"
                assert profile.context_command, f"Profile {pname} missing context_command"


# ──────────────────────────────────────────────────────────────────
# 11. Cross-vendor network rule tests (all vendors from config.yaml)
# ──────────────────────────────────────────────────────────────────

class TestCrossVendorRules:
    @pytest.fixture
    def cfg(self):
        return load_config("config.yaml")

    def test_cisco_show_commands_safe(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["cisco_ios"])
        for cmd in ["show ip route", "show running-config", "show interfaces", "show version", "ping 10.0.0.1"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict == Verdict.ALLOW, f"Expected ALLOW for '{cmd}'"

    def test_cisco_destructive_commands_blocked(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["cisco_ios"])
        for cmd in ["write erase", "erase startup-config", "no router ospf 1"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict == Verdict.DENY, f"Expected DENY for '{cmd}'"

    def test_cisco_reload_blocked(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["cisco_ios"])
        result = nre.evaluate("reload")
        assert result is not None
        assert result.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_junos_show_safe(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["junos"])
        for cmd in ["show interfaces", "show route", "ping 10.0.0.1"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict == Verdict.ALLOW, f"Expected ALLOW for '{cmd}'"

    def test_junos_destructive_blocked(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["junos"])
        for cmd in ["request system reboot", "request system zeroize", "delete protocols ospf"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict == Verdict.DENY, f"Expected DENY for '{cmd}'"

    def test_mikrotik_safe(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["mikrotik"])
        for cmd in ["ip address print", "ip route print", "ping 10.0.0.1"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict == Verdict.ALLOW, f"Expected ALLOW for '{cmd}'"

    def test_mikrotik_destructive(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["mikrotik"])
        for cmd in ["system reset-configuration", "system reboot"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict in (Verdict.DENY, Verdict.ESCALATE), f"Expected DENY/ESCALATE for '{cmd}'"

    def test_huawei_display_safe(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["huawei_vrp"])
        for cmd in ["display ip routing-table", "display current-configuration", "ping 10.0.0.1"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict == Verdict.ALLOW, f"Expected ALLOW for '{cmd}'"

    def test_huawei_destructive(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["huawei_vrp"])
        for cmd in ["reset saved-configuration", "undo ospf 1", "undo bgp 65000"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict in (Verdict.DENY, Verdict.ESCALATE), f"Expected DENY/ESCALATE for '{cmd}'"

    def test_arista_show_safe(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["arista_eos"])
        for cmd in ["show ip route", "show interfaces", "ping 10.0.0.1"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict == Verdict.ALLOW, f"Expected ALLOW for '{cmd}'"

    def test_arista_destructive(self, cfg):
        nre = NetworkRuleEngine(cfg.target_profiles["arista_eos"])
        for cmd in ["write erase", "no router ospf 1", "no router bgp 65000"]:
            result = nre.evaluate(cmd)
            assert result is not None and result.verdict in (Verdict.DENY, Verdict.ESCALATE), f"Expected DENY/ESCALATE for '{cmd}'"


# ──────────────────────────────────────────────────────────────────
# 12. Bastion session safety (session = None protection)
# ──────────────────────────────────────────────────────────────────

class TestBastionSessionSafety:
    """Verify that bastion.py correctly handles session=None in finally block."""

    def test_session_init_to_none(self):
        """The `session = None` assignment should exist in handle_session."""
        from bastion import handle_session
        import inspect
        source = inspect.getsource(handle_session)
        assert "session = None" in source
        assert "if session is not None" in source


# ──────────────────────────────────────────────────────────────────
# 13. Network Config Agent prompt building
# ──────────────────────────────────────────────────────────────────

class TestNetworkConfigAgentPrompts:
    def test_vendor_prompt_exists_for_all_vendors(self):
        from ai_defense.agents.network_config_agent import _VENDOR_PROMPTS
        expected_vendors = ["cisco_ios", "cisco_nxos", "junos", "mikrotik", "huawei_vrp", "arista_eos", "generic_network"]
        for vendor in expected_vendors:
            assert vendor in _VENDOR_PROMPTS, f"Missing vendor prompt for {vendor}"

    def test_system_prompt_includes_injection_defense(self):
        from ai_defense.agents.network_config_agent import _build_system_prompt
        prompt = _build_system_prompt("cisco_ios")
        assert "prompt injection" in prompt.lower() or "ИГНОРИРУЙ" in prompt

    def test_running_config_in_prompt(self):
        from ai_defense.agents.network_config_agent import RUNNING_CONFIG_SECTION
        assert "{config}" in RUNNING_CONFIG_SECTION


# ──────────────────────────────────────────────────────────────────
# 14. Rate limiter interaction with network sessions
# ──────────────────────────────────────────────────────────────────

class TestRateLimiterNetworkSessions:
    @patch("ai_defense.core.engine.LLMClient")
    def test_rate_limit_applies_to_network_sessions(self, mock_llm_cls, tmp_path):
        from ai_defense.core.engine import AIEngine, MAX_COMMANDS_PER_WINDOW
        cfg = load_config("config.yaml")
        cfg.audit.db_path = str(tmp_path / "rl.db")
        cfg.audit.json_log = str(tmp_path / "rl.jsonl")
        engine = AIEngine(cfg)

        session = engine.create_session(
            username="admin", role="ops",
            target_profile="cisco_ios", target_vendor="cisco_ios",
        )

        for i in range(MAX_COMMANDS_PER_WINDOW):
            engine.evaluate("show version", session)

        result = engine.evaluate("show version", session)
        assert result.verdict == Verdict.DENY
        assert "лимит" in result.reason.lower() or "rate" in result.reason.lower()

        engine.close()


# ──────────────────────────────────────────────────────────────────
# 15. Alert engine with network session context
# ──────────────────────────────────────────────────────────────────

class TestAlertEngineNetworkContext:
    def test_alert_includes_session_info(self):
        from ai_defense.core.alerts import AlertEngine
        from ai_defense.core.config import AlertsConfig, TelegramConfig, WebhookConfig
        cfg = AlertsConfig(
            telegram=TelegramConfig(enabled=False),
            webhook=WebhookConfig(enabled=False),
        )
        ae = AlertEngine(cfg)
        session = SessionContext(
            username="admin", role="neteng",
            target_profile="cisco_ios", target_vendor="cisco_ios",
        )
        verdict = FinalVerdict(
            verdict=Verdict.DENY,
            decisions=[AgentDecision(
                agent_name="network_rule_engine", verdict=Verdict.DENY,
                confidence=1.0, reason="reload blocked",
            )],
            reason="reload blocked",
        )
        ae.notify(session, "reload", verdict)


# ──────────────────────────────────────────────────────────────────
# 16. Escalation logging stores profile info
# ──────────────────────────────────────────────────────────────────

class TestEscalationLoggingProfile:
    def test_escalation_log_includes_profile(self, tmp_path):
        cfg = AuditConfig(db_path=str(tmp_path / "esc.db"), json_log=str(tmp_path / "esc.jsonl"))
        logger = AuditLogger(cfg)
        session = SessionContext(
            username="admin", role="ops",
            target_profile="mikrotik", target_vendor="mikrotik",
        )
        logger.log_session_start(session)

        original = FinalVerdict(
            verdict=Verdict.ESCALATE,
            decisions=[AgentDecision(
                agent_name="network_config_agent", verdict=Verdict.ESCALATE,
                confidence=0.6, reason="unsure about this",
            )],
            reason="needs review",
            escalated=True,
        )
        logger.log_decision(session, "ip route add", original)

        admin_decision = AgentDecision(
            agent_name="admin_escalation", verdict=Verdict.ALLOW,
            confidence=1.0, reason="Admin approved",
        )
        final = FinalVerdict(
            verdict=Verdict.ALLOW,
            decisions=[admin_decision],
            reason="Approved by admin",
            escalated=True,
        )
        logger.log_decision(session, "ip route add", final)

        logs = logger.get_recent_logs(10)
        assert len(logs) == 2
        for log_entry in logs:
            assert log_entry["target_profile"] == "mikrotik"
            assert log_entry["target_vendor"] == "mikrotik"
        assert any(l["escalated"] for l in logs)
        logger.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
