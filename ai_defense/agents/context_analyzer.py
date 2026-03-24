from __future__ import annotations

import logging
import time

from ..core.llm_client import LLMClient
from ..core.models import (
    AgentDecision,
    CommandCategory,
    SessionContext,
    Severity,
    Verdict,
)

log = logging.getLogger("ai_defense.agent.context")

SYSTEM_PROMPT = """\
Ты — агент контекстного анализа SSH-бастиона. Ты анализируешь не одну команду, а ЦЕПОЧКУ команд в рамках сессии, чтобы выявить подозрительные паттерны поведения.

Ты получишь:
1. Историю команд текущей сессии
2. Новую команду, которую нужно оценить

Подозрительные паттерны:
- Разведка перед атакой: ls → find → cat /etc/passwd → ...
- Подготовка к удалению: cd / → ls → rm -rf
- Эксфильтрация: cat sensitive_file → base64 → curl/scp наружу
- Скрытие следов: выполнение команд → history -c → unset HISTFILE
- Lateral movement: ssh/scp к другим хостам из сессии
- Privilege escalation цепочка: whoami → sudo -l → sudo su
- Необычная активность: аномально много команд за короткое время
- Переключение контекста: резкая смена типа операций (от мониторинга к модификации)

Ответь СТРОГО в формате JSON (без markdown-обёртки):
{
  "verdict": "allow" | "deny" | "escalate",
  "category": "safe" | "risky" | "destructive" | "recon" | "exfil" | "privesc",
  "confidence": 0.0-1.0,
  "severity": "low" | "medium" | "high" | "critical",
  "reason": "объяснение на русском с упоминанием обнаруженного паттерна",
  "pattern_detected": "название паттерна или null"
}"""


class ContextAnalyzerAgent:
    """Agent 2: анализ команды в контексте всей сессии."""

    NAME = "context_analyzer"

    def __init__(self, llm: LLMClient, max_history: int = 50) -> None:
        self._llm = llm
        self._max_history = max_history

    def evaluate(self, command: str, session: SessionContext) -> AgentDecision:
        t0 = time.perf_counter()

        history = session.command_history_text(self._max_history)

        user_prompt = (
            f"=== История сессии ===\n"
            f"Пользователь: {session.username or 'unknown'}\n"
            f"Роль: {session.role or 'unknown'}\n"
            f"Количество команд в сессии: {len(session.commands)}\n"
            f"\n{history}\n\n"
            f"=== Новая команда для оценки ===\n"
            f"{command}"
        )

        try:
            data = self._llm.chat_json(SYSTEM_PROMPT, user_prompt)
            elapsed = (time.perf_counter() - t0) * 1000

            if "error" in data:
                return AgentDecision(
                    agent_name=self.NAME,
                    verdict=Verdict.ESCALATE,
                    confidence=0.0,
                    reason=f"LLM невалидный ответ: {data.get('raw', '')[:100]}",
                    elapsed_ms=elapsed,
                )

            verdict = Verdict(data.get("verdict", "escalate"))
            category = CommandCategory(data.get("category", "unknown"))
            severity = Severity(data.get("severity", "medium"))
            confidence = float(data.get("confidence", 0.5))
            reason = data.get("reason", "")
            pattern = data.get("pattern_detected")
            if pattern:
                reason = f"[Паттерн: {pattern}] {reason}"

            return AgentDecision(
                agent_name=self.NAME,
                verdict=verdict,
                confidence=confidence,
                category=category,
                reason=reason,
                severity=severity,
                elapsed_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            log.error("ContextAnalyzer error: %s", exc)
            return AgentDecision(
                agent_name=self.NAME,
                verdict=Verdict.ESCALATE,
                confidence=0.0,
                reason=f"Ошибка агента: {exc}",
                elapsed_ms=elapsed,
            )
