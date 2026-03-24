from __future__ import annotations

import collections
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from ..agents.command_classifier import CommandClassifierAgent
from ..agents.context_analyzer import ContextAnalyzerAgent
from ..agents.network_config_agent import NetworkConfigAgent
from ..agents.policy_enforcer import PolicyEnforcerAgent
from .alerts import AlertEngine
from .audit import AuditLogger
from .config import AppConfig, TargetProfile
from .consensus import ConsensusEngine
from .llm_client import LLMClient
from .models import AgentDecision, FinalVerdict, SessionContext, Verdict
from .network_rule_engine import NetworkRuleEngine
from .rule_engine import RuleEngine

MAX_COMMANDS_PER_WINDOW = 30
RATE_WINDOW_SECONDS = 60.0
SCRIPT_FETCH_TIMEOUT = 3
SCRIPT_MAX_BYTES = 4096

log = logging.getLogger("ai_defense.engine")

_INTERPRETER_RE = re.compile(
    r"^(?:sudo\s+)?(?:bash|sh|zsh|dash|python[23]?|perl|ruby|node|php|lua|Rscript)\s+(.+)",
)

_DIRECT_EXEC_RE = re.compile(
    r"^(?:sudo\s+)?(\./[^\s;|&]+|/(?:tmp|home|var|opt|dev/shm)[^\s;|&]*)",
)

_SOURCE_RE = re.compile(
    r"^(?:source|\.)\s+(.+)",
)

_KNOWN_SYSTEM_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/")


def _extract_script_path(command: str) -> str | None:
    """Extract the script file path from a command, or None if not a script execution."""
    cmd = command.strip()

    m = _INTERPRETER_RE.match(cmd)
    if m:
        path = m.group(1).strip().strip("'\"").split()[0]
        return path

    m = _SOURCE_RE.match(cmd)
    if m:
        path = m.group(1).strip().strip("'\"").split()[0]
        return path

    m = _DIRECT_EXEC_RE.match(cmd)
    if m:
        path = m.group(1).strip()
        if any(path.startswith(d) for d in _KNOWN_SYSTEM_DIRS):
            return None
        return path

    return None


def _is_binary(data: bytes) -> bool:
    """Check if data looks like a binary file (contains null bytes in first 512 bytes)."""
    return b"\x00" in data[:512]


def _fetch_script_content(ssh_client: Any, script_path: str) -> tuple[str, str]:
    """Read script content from target server via SSH.

    Returns (content, status) where status is one of:
      "text"    — readable script content
      "binary"  — binary file, content is extracted strings
      "error"   — could not read, content is error description
    """
    try:
        cmd = f"head -c {SCRIPT_MAX_BYTES} {_shell_quote(script_path)} 2>&1"
        _, stdout, stderr = ssh_client.exec_command(cmd, timeout=SCRIPT_FETCH_TIMEOUT)
        raw = stdout.read(SCRIPT_MAX_BYTES + 1)

        if not raw:
            err = stderr.read(1024).decode("utf-8", errors="ignore").strip()
            return err or "Файл пуст или не найден", "error"

        if _is_binary(raw):
            str_cmd = f"strings {_shell_quote(script_path)} 2>/dev/null | head -200"
            _, str_stdout, _ = ssh_client.exec_command(str_cmd, timeout=SCRIPT_FETCH_TIMEOUT)
            strings_out = str_stdout.read(SCRIPT_MAX_BYTES).decode("utf-8", errors="ignore")
            if strings_out.strip():
                return strings_out.strip(), "binary"
            return "Бинарный файл, строки не извлечены", "binary"

        return raw.decode("utf-8", errors="ignore"), "text"

    except Exception as exc:
        log.warning("Failed to fetch script %s: %s", script_path, exc)
        return f"Ошибка чтения: {exc}", "error"


def _shell_quote(path: str) -> str:
    """Minimal shell quoting to prevent injection when reading files."""
    return "'" + path.replace("'", "'\\''") + "'"


NETWORK_CONFIG_FETCH_TIMEOUT = 10


def fetch_network_config(ssh_client: Any, profile: TargetProfile) -> str:
    """Fetch running-config from network device.

    Tries exec_command first; if the device doesn't support it (common for
    Cisco/Huawei/MikroTik), falls back to sending the command through a
    temporary interactive shell channel.
    """
    if not profile.context_command:
        return ""
    cmd = profile.context_command
    max_bytes = profile.context_max_bytes or 16384

    config = _fetch_via_exec(ssh_client, cmd, max_bytes)
    if config:
        return config

    config = _fetch_via_shell(ssh_client, cmd, max_bytes)
    return config


def _fetch_via_exec(ssh_client: Any, cmd: str, max_bytes: int) -> str:
    try:
        _, stdout, stderr = ssh_client.exec_command(cmd, timeout=NETWORK_CONFIG_FETCH_TIMEOUT)
        raw = stdout.read(max_bytes + 1)
        if not raw:
            err = stderr.read(1024).decode("utf-8", errors="ignore").strip()
            log.debug("exec_command empty for '%s': %s", cmd, err)
            return ""
        config = raw.decode("utf-8", errors="ignore")
        log.info("Fetched %d bytes of network config via exec_command '%s'", len(config), cmd)
        return config
    except Exception as exc:
        log.debug("exec_command failed for '%s': %s — will try interactive shell", cmd, exc)
        return ""


def _fetch_via_shell(ssh_client: Any, cmd: str, max_bytes: int) -> str:
    """Fetch config by sending the command through an interactive shell channel.
    Many network devices (Cisco, Huawei, MikroTik) only support this method."""
    import time as _time
    try:
        chan = ssh_client.invoke_shell()
        _time.sleep(0.5)
        if chan.recv_ready():
            chan.recv(4096)

        chan.send(cmd + "\n")
        _time.sleep(1)

        chunks: list[bytes] = []
        total = 0
        deadline = _time.monotonic() + NETWORK_CONFIG_FETCH_TIMEOUT
        while _time.monotonic() < deadline and total < max_bytes:
            if chan.recv_ready():
                chunk = chan.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                _time.sleep(0.1)
            else:
                _time.sleep(0.3)
                if not chan.recv_ready():
                    break

        chan.close()

        if not chunks:
            log.warning("Interactive shell returned no data for '%s'", cmd)
            return ""

        raw = b"".join(chunks).decode("utf-8", errors="ignore")
        lines = raw.splitlines()
        if lines and cmd in lines[0]:
            lines = lines[1:]
        config = "\n".join(lines)
        log.info("Fetched %d bytes of network config via interactive shell '%s'", len(config), cmd)
        return config
    except Exception as exc:
        log.warning("Failed to fetch network config via interactive shell: %s", exc)
        return ""


CLR_RESET = "\033[0m"
CLR_SYSTEM = "\033[93m"
CLR_SUCCESS = "\033[92m"
CLR_ERROR = "\033[91m"
CLR_WARN = "\033[33m"
CLR_DIM = "\033[90m"
CLR_BOLD = "\033[1m"
CLR_CYAN = "\033[96m"


def _severity_color(sev: str) -> str:
    return {
        "low": CLR_SUCCESS,
        "medium": CLR_WARN,
        "high": CLR_ERROR,
        "critical": f"{CLR_BOLD}{CLR_ERROR}",
    }.get(sev, CLR_RESET)


class AIEngine:
    """Orchestrator: rule engine → parallel agents → consensus → audit + alerts."""

    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self._rule_engine = RuleEngine(cfg.rules)
        self._llm = LLMClient(cfg.llm)

        cc = cfg.agents.get("command_classifier")
        self._classifier = CommandClassifierAgent(self._llm) if cc and cc.enabled else None

        ca = cfg.agents.get("context_analyzer")
        self._context = ContextAnalyzerAgent(self._llm, max_history=ca.max_history if ca else 50) if ca and ca.enabled else None

        pe = cfg.agents.get("policy_enforcer")
        self._policy = PolicyEnforcerAgent(self._llm, cfg.rbac) if pe and pe.enabled else None

        weights = {}
        for name, toggle in cfg.agents.items():
            weights[name] = toggle.weight
        self._consensus = ConsensusEngine(cfg.consensus, weights)

        self._audit = AuditLogger(cfg.audit)
        self._alerts = AlertEngine(cfg.alerts)
        self._executor = ThreadPoolExecutor(max_workers=3)
        self._rate_buckets: dict[str, collections.deque] = {}
        self._audit.cleanup_old_records()

        self._network_rule_engines: dict[str, NetworkRuleEngine] = {}
        self._network_agents: dict[str, NetworkConfigAgent] = {}
        for pname, profile in cfg.target_profiles.items():
            if profile.type == "network":
                self._network_rule_engines[pname] = NetworkRuleEngine(profile)
                self._network_agents[pname] = NetworkConfigAgent(self._llm, vendor=profile.vendor or "generic_network")

    def create_session(self, username: str = "", role: str = "",
                       target_profile: str = "", target_vendor: str = "") -> SessionContext:
        session = SessionContext(username=username, role=role,
                                target_profile=target_profile, target_vendor=target_vendor)
        self._audit.log_session_start(session)
        profile_info = f" profile={target_profile} vendor={target_vendor}" if target_profile else ""
        log.info("Session started: %s user=%s role=%s%s", session.session_id, username, role, profile_info)
        return session

    def get_profile(self, name: str) -> TargetProfile | None:
        return self.cfg.target_profiles.get(name)

    def is_network_session(self, session: SessionContext) -> bool:
        profile = self.cfg.target_profiles.get(session.target_profile)
        return profile is not None and profile.type == "network"

    def end_session(self, session: SessionContext) -> None:
        self._audit.log_session_end(session)
        self._rate_buckets.pop(session.session_id, None)
        log.info("Session ended: %s (%d commands)", session.session_id, len(session.commands))

    def _check_rate_limit(self, session: SessionContext) -> FinalVerdict | None:
        now = time.monotonic()
        sid = session.session_id
        if sid not in self._rate_buckets:
            self._rate_buckets[sid] = collections.deque()
        bucket = self._rate_buckets[sid]
        while bucket and now - bucket[0] > RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= MAX_COMMANDS_PER_WINDOW:
            return FinalVerdict(
                verdict=Verdict.DENY,
                decisions=[AgentDecision(
                    agent_name="rate_limiter",
                    verdict=Verdict.DENY,
                    confidence=1.0,
                    reason=f"Превышен лимит: {MAX_COMMANDS_PER_WINDOW} команд за {RATE_WINDOW_SECONDS:.0f}с",
                )],
                reason=f"Rate limit: {MAX_COMMANDS_PER_WINDOW} cmd/{RATE_WINDOW_SECONDS:.0f}s exceeded",
            )
        bucket.append(now)
        return None

    def evaluate(self, command: str, session: SessionContext, ssh_client: Any = None) -> FinalVerdict:
        t0 = time.perf_counter()

        rate_verdict = self._check_rate_limit(session)
        if rate_verdict:
            self._print_verdict(command, rate_verdict, (time.perf_counter() - t0) * 1000)
            session.add_command(command, rate_verdict.verdict)
            self._audit.log_decision(session, command, rate_verdict)
            return rate_verdict

        if self.is_network_session(session):
            return self._evaluate_network(command, session, t0)

        rule_decision = self._rule_engine.evaluate(command)
        if rule_decision is not None:
            verdict = FinalVerdict(
                verdict=rule_decision.verdict,
                decisions=[rule_decision],
                reason=rule_decision.reason,
            )
            self._print_verdict(command, verdict, (time.perf_counter() - t0) * 1000)
            session.add_command(command, verdict.verdict)
            self._audit.log_decision(session, command, verdict)
            if verdict.verdict in (Verdict.DENY, Verdict.ESCALATE):
                self._alerts.notify(session, command, verdict)
            return verdict

        enriched_command = command
        script_content: str | None = None
        script_status: str | None = None
        script_path: str | None = _extract_script_path(command)

        if script_path and ssh_client:
            log.info("Script detected: %s — fetching content from target", script_path)
            content, status = _fetch_script_content(ssh_client, script_path)
            script_content = content
            script_status = status

            if status == "binary":
                binary_scan = self._rule_engine.scan_strings(content)
                if binary_scan is not None:
                    binary_scan.reason = f"[бинарный файл {script_path}] {binary_scan.reason}"
                    verdict = FinalVerdict(
                        verdict=binary_scan.verdict,
                        decisions=[binary_scan],
                        reason=binary_scan.reason,
                    )
                    self._print_verdict(command, verdict, (time.perf_counter() - t0) * 1000)
                    session.add_command(command, verdict.verdict)
                    self._audit.log_decision(session, command, verdict)
                    if verdict.verdict in (Verdict.DENY, Verdict.ESCALATE):
                        self._alerts.notify(session, command, verdict)
                    return verdict

                enriched_command = (
                    f"{command}\n\n"
                    f"--- Извлечённые строки из бинарного файла {script_path} ---\n"
                    f"{content[:2048]}"
                )
            elif status == "text":
                enriched_command = (
                    f"{command}\n\n"
                    f"--- Содержимое скрипта {script_path} ---\n"
                    f"{content}"
                )
            elif status == "error":
                enriched_command = (
                    f"{command}\n\n"
                    f"--- Не удалось прочитать файл {script_path}: {content} ---"
                )
        elif script_path and not ssh_client:
            log.debug("Script detected (%s) but no ssh_client — skipping content fetch", script_path)

        decisions: list[AgentDecision] = []
        futures = {}

        if self._classifier:
            futures[self._executor.submit(self._classifier.evaluate, enriched_command)] = "classifier"
        if self._context:
            futures[self._executor.submit(self._context.evaluate, enriched_command, session)] = "context"
        if self._policy:
            futures[self._executor.submit(self._policy.evaluate, command, session.username, session.role)] = "policy"

        for future in as_completed(futures):
            try:
                decisions.append(future.result())
            except Exception as exc:
                agent_name = futures[future]
                log.error("Agent %s failed: %s", agent_name, exc)
                decisions.append(AgentDecision(
                    agent_name=agent_name,
                    verdict=Verdict.ESCALATE,
                    confidence=0.0,
                    reason=f"Ошибка: {exc}",
                ))

        for d in decisions:
            if d.agent_name == "policy_enforcer" and d.verdict == Verdict.DENY \
                    and d.confidence >= 0.95 and d.reason.startswith("RBAC:"):
                verdict = FinalVerdict(
                    verdict=Verdict.DENY,
                    decisions=decisions,
                    reason=d.reason,
                )
                elapsed = (time.perf_counter() - t0) * 1000
                self._print_verdict(command, verdict, elapsed)
                session.add_command(command, verdict.verdict)
                self._audit.log_decision(session, command, verdict)
                self._alerts.notify(session, command, verdict)
                return verdict

        verdict = self._consensus.decide(decisions)
        elapsed = (time.perf_counter() - t0) * 1000

        self._print_verdict(command, verdict, elapsed)
        session.add_command(command, verdict.verdict)
        self._audit.log_decision(session, command, verdict)

        if verdict.verdict in (Verdict.DENY, Verdict.ESCALATE):
            self._alerts.notify(session, command, verdict)

        return verdict

    def _evaluate_network(self, command: str, session: SessionContext, t0: float) -> FinalVerdict:
        """Evaluation path for network equipment sessions."""
        pname = session.target_profile
        nre = self._network_rule_engines.get(pname)
        net_agent = self._network_agents.get(pname)

        if nre:
            rule_decision = nre.evaluate(command)
            if rule_decision is not None:
                verdict = FinalVerdict(
                    verdict=rule_decision.verdict,
                    decisions=[rule_decision],
                    reason=rule_decision.reason,
                )
                self._print_verdict(command, verdict, (time.perf_counter() - t0) * 1000)
                session.add_command(command, verdict.verdict)
                self._audit.log_decision(session, command, verdict)
                if verdict.verdict in (Verdict.DENY, Verdict.ESCALATE):
                    self._alerts.notify(session, command, verdict)
                return verdict

        decisions: list[AgentDecision] = []
        futures = {}

        if net_agent:
            futures[self._executor.submit(net_agent.evaluate, command, session)] = "network_config_agent"

        if self._policy:
            futures[self._executor.submit(self._policy.evaluate, command, session.username, session.role)] = "policy"

        for future in as_completed(futures):
            try:
                decisions.append(future.result())
            except Exception as exc:
                agent_name = futures[future]
                log.error("Agent %s failed: %s", agent_name, exc)
                decisions.append(AgentDecision(
                    agent_name=agent_name,
                    verdict=Verdict.ESCALATE,
                    confidence=0.0,
                    reason=f"Ошибка: {exc}",
                ))

        for d in decisions:
            if d.agent_name == "policy_enforcer" and d.verdict == Verdict.DENY \
                    and d.confidence >= 0.95 and d.reason.startswith("RBAC:"):
                verdict = FinalVerdict(
                    verdict=Verdict.DENY,
                    decisions=decisions,
                    reason=d.reason,
                )
                elapsed = (time.perf_counter() - t0) * 1000
                self._print_verdict(command, verdict, elapsed)
                session.add_command(command, verdict.verdict)
                self._audit.log_decision(session, command, verdict)
                self._alerts.notify(session, command, verdict)
                return verdict

        verdict = self._consensus.decide(decisions)
        elapsed = (time.perf_counter() - t0) * 1000

        self._print_verdict(command, verdict, elapsed)
        session.add_command(command, verdict.verdict)
        self._audit.log_decision(session, command, verdict)

        if verdict.verdict in (Verdict.DENY, Verdict.ESCALATE):
            self._alerts.notify(session, command, verdict)

        return verdict

    def _print_verdict(self, command: str, verdict: FinalVerdict, elapsed_ms: float) -> None:
        v = verdict.verdict.value.upper()
        if verdict.verdict == Verdict.ALLOW:
            vc = CLR_SUCCESS
        elif verdict.verdict == Verdict.DENY:
            vc = CLR_ERROR
        else:
            vc = CLR_WARN

        try:
            tw = os.get_terminal_size().columns
        except (AttributeError, ValueError, OSError):
            tw = 80
        tw = max(tw, 40)
        rule = min(tw, 80)

        print(f"\n{CLR_SYSTEM}{'─' * rule}{CLR_RESET}")
        print(f"{CLR_SYSTEM}[AI] Команда:{CLR_RESET} {CLR_BOLD}{command}{CLR_RESET}")

        for d in verdict.decisions:
            sc = _severity_color(d.severity.value)
            dv = d.verdict.value.upper()
            header = f"{d.agent_name}: {dv} ({d.confidence:.0%}) [{d.severity.value}]"
            reason = d.reason
            if len(reason) > tw - 10:
                reason = reason[:tw - 13] + "..."
            print(
                f"  {CLR_CYAN}├─ {d.agent_name}{CLR_RESET}: "
                f"{vc if d.verdict == verdict.verdict else CLR_DIM}{dv}{CLR_RESET} "
                f"({d.confidence:.0%}) {sc}[{d.severity.value}]{CLR_RESET}"
            )
            if reason:
                print(f"  {CLR_DIM}│  {reason}{CLR_RESET}")
            if d.elapsed_ms:
                print(f"  {CLR_DIM}│  ⏱ {d.elapsed_ms:.0f}ms{CLR_RESET}")

        print(f"  {CLR_SYSTEM}└─ Итог: {vc}{CLR_BOLD}{v}{CLR_RESET} {CLR_DIM}({elapsed_ms:.0f}ms){CLR_RESET}")
        if verdict.reason:
            vr = verdict.reason
            if len(vr) > tw - 8:
                vr = vr[:tw - 11] + "..."
            print(f"     {CLR_DIM}{vr}{CLR_RESET}")
        print(f"{CLR_SYSTEM}{'─' * rule}{CLR_RESET}")

    @property
    def audit(self) -> AuditLogger:
        return self._audit

    def close(self) -> None:
        self._executor.shutdown(wait=False)
        self._audit.close()
