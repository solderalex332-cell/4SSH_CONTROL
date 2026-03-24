from __future__ import annotations

import re
import time

from .config import TargetProfile
from .models import (
    AgentDecision,
    CommandCategory,
    Severity,
    Verdict,
)


class NetworkRuleEngine:
    """Layer-0 instant filter for network equipment commands.

    Works analogously to RuleEngine but with vendor-specific rules loaded
    from a TargetProfile.  No shell-obfuscation normalization — network
    CLIs don't support the same tricks.
    """

    def __init__(self, profile: TargetProfile) -> None:
        self._profile = profile
        self._vendor = profile.vendor

        self._safe: set[str] = set()
        for cmd in profile.network_rules.safe_commands:
            self._safe.add(cmd.strip().lower())

        self._dangerous: list[tuple[re.Pattern, str, Severity]] = []
        for bl in profile.network_rules.dangerous_patterns:
            sev = Severity.HIGH
            try:
                sev = Severity(bl.severity)
            except ValueError:
                pass
            self._dangerous.append((re.compile(bl.pattern, re.IGNORECASE), bl.reason, sev))

        self._critical: list[tuple[re.Pattern, str, Severity]] = []
        for bl in profile.network_rules.critical_patterns:
            sev = Severity.CRITICAL
            try:
                sev = Severity(bl.severity)
            except ValueError:
                pass
            self._critical.append((re.compile(bl.pattern, re.IGNORECASE), bl.reason, sev))

        self._escalation: list[tuple[re.Pattern, str, Severity, Verdict]] = []
        for er in profile.network_rules.escalation_patterns:
            sev = Severity.HIGH
            try:
                sev = Severity(er.severity)
            except ValueError:
                pass
            action = Verdict.DENY if er.action == "deny" else Verdict.ESCALATE
            self._escalation.append((re.compile(er.pattern, re.IGNORECASE), er.reason, sev, action))

    @staticmethod
    def sanitize(raw: str) -> str:
        """Light sanitization for network CLI — just strip control chars."""
        cleaned = "".join(ch if (ch >= " " or ch in "\t\n\r") else "" for ch in raw)
        return cleaned.strip()

    def evaluate(self, command: str) -> AgentDecision | None:
        """Instant decision for network commands, or None → pass to LLM agents."""
        t0 = time.perf_counter()
        cmd = self.sanitize(command)
        if not cmd:
            return None

        normalized = cmd.lower().strip()

        base = normalized.split()[0] if normalized else ""
        if normalized in self._safe or base in self._safe:
            return AgentDecision(
                agent_name="network_rule_engine",
                verdict=Verdict.ALLOW,
                confidence=1.0 if normalized in self._safe else 0.9,
                category=CommandCategory.SAFE,
                reason=f"[{self._vendor}] Безопасная команда",
                severity=Severity.LOW,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        for pattern, reason, severity in self._critical:
            if pattern.search(cmd):
                return AgentDecision(
                    agent_name="network_rule_engine",
                    verdict=Verdict.DENY,
                    confidence=1.0,
                    category=CommandCategory.DESTRUCTIVE,
                    reason=f"[{self._vendor}] КРИТИЧНАЯ: {reason}",
                    severity=severity,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                )

        for pattern, reason, severity in self._dangerous:
            if pattern.search(cmd):
                verdict = Verdict.DENY if severity in (Severity.CRITICAL,) else Verdict.ESCALATE
                return AgentDecision(
                    agent_name="network_rule_engine",
                    verdict=verdict,
                    confidence=1.0,
                    category=CommandCategory.DESTRUCTIVE if verdict == Verdict.DENY else CommandCategory.RISKY,
                    reason=f"[{self._vendor}] Опасная команда: {reason}",
                    severity=severity,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                )

        for pattern, reason, severity, action in self._escalation:
            if pattern.search(cmd):
                return AgentDecision(
                    agent_name="network_rule_engine",
                    verdict=action,
                    confidence=1.0,
                    category=CommandCategory.RISKY,
                    reason=f"[{self._vendor}] Контекстное: {reason}",
                    severity=severity,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                )

        return None
