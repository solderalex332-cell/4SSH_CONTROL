from __future__ import annotations

import re
import time

from .config import RulesConfig
from .models import (
    AgentDecision,
    CommandCategory,
    Severity,
    Verdict,
)


_CHAIN_SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\||`|\$\()\s*")

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07")


class RuleEngine:
    """Layer-0 instant filter: whitelist/blacklist/sensitive paths."""

    def __init__(self, rules: RulesConfig) -> None:
        self._whitelist: set[str] = set()
        for cmd in rules.whitelist:
            self._whitelist.add(cmd.strip().lower())

        self._blacklist: list[tuple[re.Pattern, str, Severity]] = []
        for bl in rules.blacklist:
            sev = Severity.HIGH
            try:
                sev = Severity(bl.severity)
            except ValueError:
                pass
            self._blacklist.append((re.compile(bl.pattern), bl.reason, sev))

        self._sensitive_paths: list[tuple[str, str, Severity, Verdict]] = []
        for sp in rules.sensitive_paths:
            sev = Severity.HIGH
            try:
                sev = Severity(sp.severity)
            except ValueError:
                pass
            action = Verdict.DENY if sp.action == "deny" else Verdict.ESCALATE
            self._sensitive_paths.append((sp.pattern, sp.reason, sev, action))

        self._dangerous_content: list[tuple[str, str, Severity]] = []
        for dc in rules.dangerous_content:
            sev = Severity.HIGH
            try:
                sev = Severity(dc.severity)
            except ValueError:
                pass
            self._dangerous_content.append((dc.pattern, dc.reason, sev))

        self._escalation_rules: list[tuple[re.Pattern, str, Severity, Verdict]] = []
        for er in rules.escalation_rules:
            sev = Severity.HIGH
            try:
                sev = Severity(er.severity)
            except ValueError:
                pass
            action = Verdict.DENY if er.action == "deny" else Verdict.ESCALATE
            self._escalation_rules.append((re.compile(er.pattern, re.IGNORECASE), er.reason, sev, action))

    @staticmethod
    def sanitize(raw: str) -> str:
        """Strip ANSI escapes and control characters from raw terminal input."""
        cleaned = _ANSI_ESCAPE_RE.sub("", raw)
        cleaned = "".join(ch for ch in cleaned if ch >= " " or ch in "\t\n\r")
        return cleaned.strip()

    def evaluate(self, command: str) -> AgentDecision | None:
        """Return an instant decision if the rule matches, else None (pass to agents)."""
        t0 = time.perf_counter()
        stripped = self.sanitize(command)
        if not stripped:
            return None
        normalized = stripped.lower()

        for pattern, reason, severity in self._blacklist:
            if pattern.search(stripped):
                return AgentDecision(
                    agent_name="rule_engine",
                    verdict=Verdict.DENY,
                    confidence=1.0,
                    category=CommandCategory.DESTRUCTIVE,
                    reason=reason,
                    severity=severity,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                )

        sp_decision = self.check_sensitive_path(stripped)
        if sp_decision is not None:
            sp_decision.elapsed_ms = (time.perf_counter() - t0) * 1000
            return sp_decision

        esc_decision = self._check_escalation_rules(stripped)
        if esc_decision is not None:
            esc_decision.elapsed_ms = (time.perf_counter() - t0) * 1000
            return esc_decision

        sub_commands = _CHAIN_SPLIT_RE.split(stripped)
        has_chain = len(sub_commands) > 1
        if has_chain:
            for sub in sub_commands:
                sub = sub.strip().rstrip(")")
                if not sub:
                    continue
                sub_result = self._evaluate_single(sub)
                if sub_result and sub_result.verdict == Verdict.DENY:
                    sub_result.reason = f"[в цепочке] {sub_result.reason}"
                    sub_result.elapsed_ms = (time.perf_counter() - t0) * 1000
                    return sub_result
                sp = self.check_sensitive_path(sub)
                if sp and sp.verdict == Verdict.DENY:
                    sp.reason = f"[в цепочке] {sp.reason}"
                    sp.elapsed_ms = (time.perf_counter() - t0) * 1000
                    return sp
                sub_esc = self._check_escalation_rules(sub)
                if sub_esc and sub_esc.verdict == Verdict.DENY:
                    sub_esc.reason = f"[в цепочке] {sub_esc.reason}"
                    sub_esc.elapsed_ms = (time.perf_counter() - t0) * 1000
                    return sub_esc
            return None

        if normalized in self._whitelist:
            return AgentDecision(
                agent_name="rule_engine",
                verdict=Verdict.ALLOW,
                confidence=1.0,
                category=CommandCategory.SAFE,
                reason=f"Команда '{stripped}' в белом списке",
                severity=Severity.LOW,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        base_cmd = normalized.split()[0] if normalized else ""
        if base_cmd in self._whitelist:
            return AgentDecision(
                agent_name="rule_engine",
                verdict=Verdict.ALLOW,
                confidence=0.9,
                category=CommandCategory.SAFE,
                reason=f"Базовая команда '{base_cmd}' в белом списке",
                severity=Severity.LOW,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        return None

    def _check_escalation_rules(self, command: str) -> AgentDecision | None:
        """Context-aware rules: catch dangerous *usage patterns*, not commands wholesale."""
        for pattern, reason, severity, action in self._escalation_rules:
            if pattern.search(command):
                return AgentDecision(
                    agent_name="rule_engine",
                    verdict=action,
                    confidence=1.0,
                    category=CommandCategory.RISKY,
                    reason=f"Контекстное правило: {reason}",
                    severity=severity,
                )
        return None

    def _evaluate_single(self, command: str) -> AgentDecision | None:
        """Check a single (non-chained) command against blacklist only."""
        stripped = command.strip()
        for pattern, reason, severity in self._blacklist:
            if pattern.search(stripped):
                return AgentDecision(
                    agent_name="rule_engine",
                    verdict=Verdict.DENY,
                    confidence=1.0,
                    category=CommandCategory.DESTRUCTIVE,
                    reason=reason,
                    severity=severity,
                )
        return None

    def check_sensitive_path(self, command: str) -> AgentDecision | None:
        """Check if the command targets a sensitive file path."""
        for path_pattern, reason, severity, action in self._sensitive_paths:
            if path_pattern in command:
                return AgentDecision(
                    agent_name="rule_engine",
                    verdict=action,
                    confidence=1.0,
                    category=CommandCategory.RISKY,
                    reason=f"Чувствительный файл: {reason} ({path_pattern})",
                    severity=severity,
                )
        return None

    def scan_content(self, text: str) -> AgentDecision | None:
        """Scan text typed inside interactive programs for dangerous patterns."""
        for pattern, reason, severity in self._dangerous_content:
            if pattern in text:
                return AgentDecision(
                    agent_name="content_monitor",
                    verdict=Verdict.DENY,
                    confidence=0.95,
                    category=CommandCategory.DESTRUCTIVE,
                    reason=f"Опасное содержимое: {reason}",
                    severity=severity,
                )
        return None
