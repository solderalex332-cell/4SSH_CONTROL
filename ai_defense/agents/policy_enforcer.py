from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from ..core.config import RBACConfig, TimePolicy
from ..core.llm_client import LLMClient
from ..core.models import (
    AgentDecision,
    CommandCategory,
    Severity,
    Verdict,
)

log = logging.getLogger("ai_defense.agent.policy")

SYSTEM_PROMPT = """\
Ты — агент контроля политик SSH-бастиона. Проверяешь, соответствует ли команда политике доступа (RBAC).

Ты получишь:
1. Роль пользователя и её ограничения
2. Команду для проверки
3. Временной контекст (рабочие/нерабочие часы)

Правила:
- Если команда начинается с утилиты из denied_commands роли → deny
- Если allowed_commands содержит "*" → проверяй только denied_commands
- Если allowed_commands НЕ содержит "*" и команда НЕ начинается с утилиты из allowed_commands → escalate
- Если выполнение в нерабочие часы (high_risk_hours) → повысь severity на один уровень
- sudo перед командой → проверяй саму команду после sudo, а не слово "sudo"

Ответь СТРОГО в формате JSON (без markdown-обёртки):
{
  "verdict": "allow" | "deny" | "escalate",
  "confidence": 0.0-1.0,
  "severity": "low" | "medium" | "high" | "critical",
  "reason": "объяснение на русском",
  "policy_violation": "название нарушенной политики или null"
}"""


def _is_high_risk_time(tp: TimePolicy) -> bool:
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo(tp.timezone)
    except Exception:
        tz = timezone.utc
    now = datetime.now(tz)
    current = now.hour * 60 + now.minute
    start_h, start_m = map(int, tp.start.split(":"))
    end_h, end_m = map(int, tp.end.split(":"))
    start_min = start_h * 60 + start_m
    end_min = end_h * 60 + end_m
    if start_min <= end_min:
        return start_min <= current <= end_min
    return current >= start_min or current <= end_min


class PolicyEnforcerAgent:
    """Agent 3: RBAC и временные политики."""

    NAME = "policy_enforcer"

    def __init__(self, llm: LLMClient, rbac: RBACConfig) -> None:
        self._llm = llm
        self._rbac = rbac

    def evaluate(self, command: str, username: str, role: str) -> AgentDecision:
        t0 = time.perf_counter()

        role_policy = self._rbac.roles.get(role)
        if not role_policy:
            elapsed = (time.perf_counter() - t0) * 1000
            return AgentDecision(
                agent_name=self.NAME,
                verdict=Verdict.ESCALATE,
                confidence=0.5,
                reason=f"Роль '{role}' не найдена в политиках. Эскалация.",
                severity=Severity.MEDIUM,
                elapsed_ms=elapsed,
            )

        high_risk = _is_high_risk_time(self._rbac.time_policy)

        user_prompt = (
            f"=== Политика ===\n"
            f"Пользователь: {username}\n"
            f"Роль: {role} ({role_policy.description})\n"
            f"Разрешённые команды: {role_policy.allowed_commands}\n"
            f"Запрещённые команды: {role_policy.denied_commands}\n"
            f"Нерабочие часы (повышенный риск): {'ДА' if high_risk else 'нет'}\n"
            f"\n=== Команда ===\n{command}"
        )

        try:
            data = self._llm.chat_json(SYSTEM_PROMPT, user_prompt)
            elapsed = (time.perf_counter() - t0) * 1000

            if "error" in data:
                return AgentDecision(
                    agent_name=self.NAME,
                    verdict=Verdict.ESCALATE,
                    confidence=0.0,
                    reason=f"LLM невалидный ответ",
                    elapsed_ms=elapsed,
                )

            verdict = Verdict(data.get("verdict", "escalate"))
            severity = Severity(data.get("severity", "medium"))
            confidence = float(data.get("confidence", 0.5))
            reason = data.get("reason", "")
            violation = data.get("policy_violation")

            if high_risk and severity != Severity.CRITICAL:
                sev_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                idx = sev_order.index(severity)
                severity = sev_order[min(idx + 1, len(sev_order) - 1)]
                reason = f"[Нерабочие часы — повышенный риск] {reason}"

            if violation:
                reason = f"[Политика: {violation}] {reason}"

            return AgentDecision(
                agent_name=self.NAME,
                verdict=verdict,
                confidence=confidence,
                category=CommandCategory.UNKNOWN,
                reason=reason,
                severity=severity,
                elapsed_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            log.error("PolicyEnforcer error: %s", exc)
            return AgentDecision(
                agent_name=self.NAME,
                verdict=Verdict.ESCALATE,
                confidence=0.0,
                reason=f"Ошибка агента: {exc}",
                elapsed_ms=elapsed,
            )
