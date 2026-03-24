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


class RuleEngine:
    """Layer-0 instant filter: whitelist/blacklist regex matching."""

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

    def evaluate(self, command: str) -> AgentDecision | None:
        """Return an instant decision if the rule matches, else None (pass to agents)."""
        t0 = time.perf_counter()
        stripped = command.strip()
        normalized = stripped.lower()

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

        return None
