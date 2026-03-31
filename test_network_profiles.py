#!/usr/bin/env python3
"""Verification tests for Network Equipment Profile support."""

import sys
import re
from unittest.mock import MagicMock

sys.path.insert(0, ".")

from ai_defense.core.config import load_config, TargetProfile, NetworkProfileRules, BlacklistRule, EscalationRule
from ai_defense.core.models import SessionContext, Verdict
from ai_defense.core.network_rule_engine import NetworkRuleEngine
from ai_defense.core.engine import AIEngine, fetch_network_config
from ai_defense.agents.network_config_agent import NetworkConfigAgent, _build_system_prompt

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        print(f"  ❌ {name}" + (f"  ({detail})" if detail else ""))


# ─── 1. Config parsing ──────────────────────────────────────────────────────
print("\n═══ 1. Config: target_profiles parsed ═══")

cfg = load_config("config.yaml")

check("target_profiles loaded",
      len(cfg.target_profiles) > 0,
      f"found {len(cfg.target_profiles)}")

check("linux profile exists",
      "linux" in cfg.target_profiles)

check("cisco_ios profile exists",
      "cisco_ios" in cfg.target_profiles)

check("junos profile exists",
      "junos" in cfg.target_profiles)

check("mikrotik profile exists",
      "mikrotik" in cfg.target_profiles)

check("huawei_vrp profile exists",
      "huawei_vrp" in cfg.target_profiles)

check("arista_eos profile exists",
      "arista_eos" in cfg.target_profiles)

cisco = cfg.target_profiles["cisco_ios"]
check("cisco type=network", cisco.type == "network")
check("cisco vendor=cisco_ios", cisco.vendor == "cisco_ios")
check("cisco context_command", cisco.context_command == "show running-config")
check("cisco has safe_commands", len(cisco.network_rules.safe_commands) > 0)
check("cisco has dangerous_patterns", len(cisco.network_rules.dangerous_patterns) > 0)
check("cisco has escalation_patterns", len(cisco.network_rules.escalation_patterns) > 0)
check("cisco detect_banner not empty", len(cisco.detect_banner) > 0)
check("cisco detect_prompt not empty", len(cisco.detect_prompt) > 0)

junos = cfg.target_profiles["junos"]
check("junos vendor=junos", junos.vendor == "junos")
check("junos context_command", "show configuration" in junos.context_command)

mikrotik = cfg.target_profiles["mikrotik"]
check("mikrotik vendor=mikrotik", mikrotik.vendor == "mikrotik")
check("mikrotik context_command", mikrotik.context_command == "/export")

huawei = cfg.target_profiles["huawei_vrp"]
check("huawei vendor=huawei_vrp", huawei.vendor == "huawei_vrp")
check("huawei context_command", "display current-configuration" in huawei.context_command)

# ─── 2. SessionContext new fields ────────────────────────────────────────────
print("\n═══ 2. SessionContext: new fields ═══")

s = SessionContext(username="test", role="neteng", target_profile="cisco_ios", target_vendor="cisco_ios")
check("target_profile field", s.target_profile == "cisco_ios")
check("target_vendor field", s.target_vendor == "cisco_ios")
check("network_context default empty", s.network_context == "")

s.network_context = "interface GigE0/1\n ip address 10.0.0.1 255.255.255.0"
check("network_context settable", "10.0.0.1" in s.network_context)

# ─── 3. NetworkRuleEngine — Cisco IOS ───────────────────────────────────────
print("\n═══ 3. NetworkRuleEngine — Cisco IOS ═══")

nre_cisco = NetworkRuleEngine(cisco)

r = nre_cisco.evaluate("show running-config")
check("show running-config → ALLOW", r is not None and r.verdict == Verdict.ALLOW)

r = nre_cisco.evaluate("show ip route")
check("show ip route → ALLOW (base 'show' safe)", r is not None and r.verdict == Verdict.ALLOW)

r = nre_cisco.evaluate("ping 10.0.0.1")
check("ping → ALLOW", r is not None and r.verdict == Verdict.ALLOW)

r = nre_cisco.evaluate("write erase")
check("write erase → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE),
      f"got {r.verdict.value if r else 'None'}")

r = nre_cisco.evaluate("reload")
check("reload → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_cisco.evaluate("no router ospf 1")
check("no router ospf → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_cisco.evaluate("shutdown")
check("shutdown → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_cisco.evaluate("no ip address")
check("no ip address → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_cisco.evaluate("clear ip bgp *")
check("clear ip bgp * → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_cisco.evaluate("no spanning-tree vlan 100")
check("no spanning-tree → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_cisco.evaluate("interface GigabitEthernet0/1")
check("interface → ESCALATE (config change)",
      r is not None and r.verdict == Verdict.ESCALATE)

r = nre_cisco.evaluate("router ospf 1")
check("router ospf → ESCALATE",
      r is not None and r.verdict == Verdict.ESCALATE)

r = nre_cisco.evaluate("ip route 10.0.0.0 255.0.0.0 192.168.1.1")
check("ip route → ESCALATE",
      r is not None and r.verdict == Verdict.ESCALATE)

r = nre_cisco.evaluate("no enable secret")
check("no enable secret → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_cisco.evaluate("no aaa authentication login default local")
check("no aaa → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

# ─── 4. NetworkRuleEngine — JunOS ──────────────────────────────────────────
print("\n═══ 4. NetworkRuleEngine — JunOS ═══")

nre_junos = NetworkRuleEngine(junos)

r = nre_junos.evaluate("show interfaces terse")
check("show interfaces terse → ALLOW", r is not None and r.verdict == Verdict.ALLOW)

r = nre_junos.evaluate("request system reboot")
check("request system reboot → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_junos.evaluate("delete protocols ospf")
check("delete protocols → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_junos.evaluate("set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30")
check("set interfaces → ESCALATE",
      r is not None and r.verdict == Verdict.ESCALATE)

r = nre_junos.evaluate("commit")
check("commit → ESCALATE",
      r is not None and r.verdict == Verdict.ESCALATE)

r = nre_junos.evaluate("load override terminal")
check("load override → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

# ─── 5. NetworkRuleEngine — MikroTik ──────────────────────────────────────
print("\n═══ 5. NetworkRuleEngine — MikroTik ═══")

nre_mt = NetworkRuleEngine(mikrotik)

r = nre_mt.evaluate("ip address print")
check("ip address print → ALLOW", r is not None and r.verdict == Verdict.ALLOW)

r = nre_mt.evaluate("system reset-configuration")
check("system reset-configuration → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_mt.evaluate("system reboot")
check("system reboot → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_mt.evaluate("ip address add address=10.0.0.1/24 interface=ether1")
check("ip address add → ESCALATE",
      r is not None and r.verdict == Verdict.ESCALATE)

r = nre_mt.evaluate("ip firewall filter add chain=input action=drop")
check("ip firewall → ESCALATE",
      r is not None and r.verdict == Verdict.ESCALATE)

# ─── 6. NetworkRuleEngine — Huawei VRP ─────────────────────────────────────
print("\n═══ 6. NetworkRuleEngine — Huawei VRP ═══")

nre_hw = NetworkRuleEngine(huawei)

r = nre_hw.evaluate("display ip routing-table")
check("display ip routing-table → ALLOW", r is not None and r.verdict == Verdict.ALLOW)

r = nre_hw.evaluate("reset saved-configuration")
check("reset saved-configuration → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_hw.evaluate("undo ospf 1")
check("undo ospf → DENY/ESCALATE",
      r is not None and r.verdict in (Verdict.DENY, Verdict.ESCALATE))

r = nre_hw.evaluate("interface GigabitEthernet0/0/1")
check("interface → ESCALATE",
      r is not None and r.verdict == Verdict.ESCALATE)

# ─── 7. AIEngine — profile routing ──────────────────────────────────────────
print("\n═══ 7. AIEngine — profile routing ═══")

engine = AIEngine(cfg)

check("NetworkRuleEngines created",
      len(engine._network_rule_engines) >= 5,
      f"got {len(engine._network_rule_engines)}")
check("NetworkAgents created",
      len(engine._network_agents) >= 5,
      f"got {len(engine._network_agents)}")

session_linux = engine.create_session(username="admin", role="ops", target_profile="linux")
check("Linux session: is_network=False",
      not engine.is_network_session(session_linux))

session_cisco = engine.create_session(username="admin", role="neteng",
                                      target_profile="cisco_ios", target_vendor="cisco_ios")
check("Cisco session: is_network=True",
      engine.is_network_session(session_cisco))

from ai_defense.core.models import AgentDecision, CommandCategory, Severity

def _mock_net_agent_evaluate(cmd, session):
    return AgentDecision(
        agent_name="network_config_agent",
        verdict=Verdict.ALLOW,
        confidence=0.9,
        category=CommandCategory.SAFE,
        reason="mock",
        severity=Severity.LOW,
    )

engine._network_agents["cisco_ios"].evaluate = _mock_net_agent_evaluate
engine._policy = None

v = engine.evaluate("show ip route", session_cisco)
check("show ip route (cisco) → ALLOW via network rule engine",
      v.verdict == Verdict.ALLOW,
      f"got {v.verdict.value}")

v = engine.evaluate("write erase", session_cisco)
check("write erase (cisco) → DENY/ESCALATE via network rule engine",
      v.verdict in (Verdict.DENY, Verdict.ESCALATE),
      f"got {v.verdict.value}")

v = engine.evaluate("ls -la", session_linux)
check("ls -la (linux) → ALLOW via linux rule engine",
      v.verdict == Verdict.ALLOW,
      f"got {v.verdict.value}")

# ─── 8. NetworkConfigAgent — prompt building ────────────────────────────────
print("\n═══ 8. NetworkConfigAgent — prompts ═══")

for vendor in ["cisco_ios", "junos", "mikrotik", "huawei_vrp", "arista_eos", "generic_network"]:
    prompt = _build_system_prompt(vendor)
    check(f"Prompt for {vendor} contains vendor info",
          vendor.replace("_", " ").lower() in prompt.lower() or "ВЕНДОР" in prompt,
          f"len={len(prompt)}")

check("Prompt contains JSON format spec",
      '"verdict"' in _build_system_prompt("cisco_ios"))
check("Prompt contains prompt injection warning",
      "prompt injection" in _build_system_prompt("cisco_ios").lower())

# ─── 9. fetch_network_config (mocked) ──────────────────────────────────────
print("\n═══ 9. fetch_network_config (mocked SSH) ═══")

ssh_mock = MagicMock()
stdout_mock = MagicMock()
stdout_mock.read.return_value = b"hostname Router1\ninterface GigE0/1\n ip address 10.0.0.1 255.255.255.0\n!"
stderr_mock = MagicMock()
stderr_mock.read.return_value = b""
ssh_mock.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

profile = cisco
config = fetch_network_config(ssh_mock, profile)
check("Config fetched successfully",
      "hostname Router1" in config and "10.0.0.1" in config)

ssh_mock.exec_command.assert_called_once()
called_cmd = ssh_mock.exec_command.call_args[0][0]
check("Used correct context_command",
      called_cmd == "show running-config",
      f"got '{called_cmd}'")

ssh_err = MagicMock()
ssh_err.exec_command.side_effect = Exception("Connection timeout")
config_err = fetch_network_config(ssh_err, profile)
check("Error returns empty string", config_err == "")

# ─── 10. Profile auto-detection simulation ──────────────────────────────────
print("\n═══ 10. Profile auto-detection ═══")

from bastion import _detect_target_profile

transport_mock = MagicMock()
transport_mock.get_banner.return_value = b"Cisco IOS Software, Version 15.4"
pname, vendor = _detect_target_profile(engine, transport_mock, "")
check("Cisco IOS detected by banner",
      pname == "cisco_ios" and vendor == "cisco_ios",
      f"got {pname}/{vendor}")

transport_mock.get_banner.return_value = b""
pname, vendor = _detect_target_profile(engine, transport_mock, "RouterOS v7.1\n[admin@MikroTik] > ")
check("MikroTik detected by banner text",
      pname == "mikrotik",
      f"got {pname}/{vendor}")

transport_mock.get_banner.return_value = b"JUNOS 21.2R1.10"
pname, vendor = _detect_target_profile(engine, transport_mock, "")
check("JunOS detected by banner",
      pname == "junos" and vendor == "junos",
      f"got {pname}/{vendor}")

transport_mock.get_banner.return_value = b"Huawei Versatile Routing Platform Software"
pname, vendor = _detect_target_profile(engine, transport_mock, "")
check("Huawei VRP detected by banner",
      pname == "huawei_vrp",
      f"got {pname}/{vendor}")

transport_mock.get_banner.return_value = b"SSH-2.0-OpenSSH_8.9"
pname, vendor = _detect_target_profile(engine, transport_mock, "user@server:~$ ")
check("Linux fallback for OpenSSH",
      pname == "linux",
      f"got {pname}/{vendor}")

engine.close()

# ─── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{'═' * 60}")
print(f"  ИТОГО: {PASS} passed, {FAIL} failed  ({PASS + FAIL} total)")
print(f"{'═' * 60}")

if __name__ == "__main__":
    sys.exit(1 if FAIL else 0)
