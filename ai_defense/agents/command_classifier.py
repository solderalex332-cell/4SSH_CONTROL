from __future__ import annotations

import logging
import time

from ..core.llm_client import LLMClient
from ..core.models import (
    AgentDecision,
    CommandCategory,
    Severity,
    Verdict,
)

log = logging.getLogger("ai_defense.agent.classifier")

SYSTEM_PROMPT = """\
Ты — агент безопасности SSH-бастиона. Твоя задача — классифицировать Linux-команду.

Ответь СТРОГО в формате JSON (без markdown-обёртки):
{
  "verdict": "allow" | "deny" | "escalate",
  "category": "safe" | "risky" | "destructive" | "recon" | "exfil" | "privesc",
  "confidence": 0.0-1.0,
  "severity": "low" | "medium" | "high" | "critical",
  "reason": "краткое объяснение на русском"
}

Категории:
- safe: безопасные команды просмотра (ls, cat, ps, top, df)
- risky: потенциально опасные, но легитимные (service restart, chmod)
- destructive: удаление данных, форматирование, перезапись (rm -rf, dd, mkfs)
- recon: разведка сети/системы (nmap, скачивание /etc/shadow, masscan)
- exfil: утечка данных наружу (scp к внешнему хосту, curl -d с данными)
- privesc: повышение привилегий (sudo su, добавление пользователя в sudoers)

Правила:
- Безопасные команды → allow + safe
- Рискованные но легитимные → escalate + risky
- Деструктивные / опасные → deny + destructive/exfil/privesc
- Если не уверен → escalate, confidence < 0.7"""


class CommandClassifierAgent:
    """Agent 1: быстрая классификация одиночной команды через LLM."""

    NAME = "command_classifier"

    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    def evaluate(self, command: str) -> AgentDecision:
        t0 = time.perf_counter()
        try:
            data = self._llm.chat_json(SYSTEM_PROMPT, f"Команда: {command}")
            elapsed = (time.perf_counter() - t0) * 1000

            if "error" in data:
                return AgentDecision(
                    agent_name=self.NAME,
                    verdict=Verdict.ESCALATE,
                    confidence=0.0,
                    reason=f"LLM вернул невалидный JSON: {data.get('raw', '')[:100]}",
                    elapsed_ms=elapsed,
                )

            verdict = Verdict(data.get("verdict", "escalate"))
            category = CommandCategory(data.get("category", "unknown"))
            severity = Severity(data.get("severity", "medium"))
            confidence = float(data.get("confidence", 0.5))
            reason = data.get("reason", "")

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
            log.error("CommandClassifier error: %s", exc)
            return AgentDecision(
                agent_name=self.NAME,
                verdict=Verdict.ESCALATE,
                confidence=0.0,
                reason=f"Ошибка агента: {exc}",
                elapsed_ms=elapsed,
            )
