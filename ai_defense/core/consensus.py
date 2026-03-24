from __future__ import annotations

from .config import AppConfig, ConsensusConfig
from .models import AgentDecision, FinalVerdict, Severity, Verdict


class ConsensusEngine:
    """Aggregates agent decisions into a single final verdict via weighted voting."""

    def __init__(self, cfg: ConsensusConfig, agent_weights: dict[str, float] | None = None) -> None:
        self._cfg = cfg
        self._weights = agent_weights or {}

    def decide(self, decisions: list[AgentDecision]) -> FinalVerdict:
        if not decisions:
            return FinalVerdict(verdict=Verdict.ESCALATE, reason="Нет решений от агентов")

        strategy = self._cfg.strategy

        if strategy == "any_deny":
            return self._any_deny(decisions)
        if strategy == "unanimous":
            return self._unanimous(decisions)
        return self._weighted_majority(decisions)

    def _any_deny(self, decisions: list[AgentDecision]) -> FinalVerdict:
        for d in decisions:
            if d.verdict == Verdict.DENY:
                return FinalVerdict(
                    verdict=Verdict.DENY,
                    decisions=decisions,
                    reason=f"Агент '{d.agent_name}' заблокировал: {d.reason}",
                )
        if any(d.verdict == Verdict.ESCALATE for d in decisions):
            return FinalVerdict(
                verdict=Verdict.ESCALATE,
                decisions=decisions,
                reason="Один или несколько агентов запросили эскалацию",
                escalated=True,
            )
        return FinalVerdict(verdict=Verdict.ALLOW, decisions=decisions, reason="Все агенты разрешили")

    def _unanimous(self, decisions: list[AgentDecision]) -> FinalVerdict:
        verdicts = {d.verdict for d in decisions}
        if len(verdicts) == 1:
            v = verdicts.pop()
            return FinalVerdict(verdict=v, decisions=decisions, reason="Единогласное решение")
        if Verdict.DENY in verdicts:
            deniers = [d for d in decisions if d.verdict == Verdict.DENY]
            reasons = "; ".join(f"{d.agent_name}: {d.reason}" for d in deniers)
            return FinalVerdict(verdict=Verdict.DENY, decisions=decisions, reason=reasons)
        return FinalVerdict(
            verdict=Verdict.ESCALATE,
            decisions=decisions,
            reason="Нет единогласия — эскалация",
            escalated=True,
        )

    def _weighted_majority(self, decisions: list[AgentDecision]) -> FinalVerdict:
        score_allow = 0.0
        score_deny = 0.0
        score_escalate = 0.0

        for d in decisions:
            w = self._weights.get(d.agent_name, 1.0) * d.confidence
            if d.verdict == Verdict.ALLOW:
                score_allow += w
            elif d.verdict == Verdict.DENY:
                score_deny += w
            else:
                score_escalate += w

        total = score_allow + score_deny + score_escalate
        if total == 0:
            return FinalVerdict(
                verdict=Verdict.ESCALATE,
                decisions=decisions,
                reason="Нулевая уверенность всех агентов",
                escalated=True,
            )

        deny_ratio = score_deny / total

        if deny_ratio >= self._cfg.deny_threshold:
            deniers = [d for d in decisions if d.verdict == Verdict.DENY]
            reasons = "; ".join(f"{d.agent_name}: {d.reason}" for d in deniers)
            return FinalVerdict(
                verdict=Verdict.DENY,
                decisions=decisions,
                reason=f"Взвешенный deny={deny_ratio:.0%}: {reasons}",
            )

        allow_ratio = score_allow / total
        if allow_ratio > (1 - self._cfg.deny_threshold):
            return FinalVerdict(
                verdict=Verdict.ALLOW,
                decisions=decisions,
                reason=f"Взвешенный allow={allow_ratio:.0%}",
            )

        if self._cfg.escalate_on_disagreement:
            return FinalVerdict(
                verdict=Verdict.ESCALATE,
                decisions=decisions,
                reason=f"Разногласие (allow={score_allow:.1f}, deny={score_deny:.1f}, escalate={score_escalate:.1f})",
                escalated=True,
            )

        return FinalVerdict(
            verdict=Verdict.ALLOW,
            decisions=decisions,
            reason=f"Нет консенсуса, по умолчанию allow (allow={score_allow:.1f}, deny={score_deny:.1f})",
        )
