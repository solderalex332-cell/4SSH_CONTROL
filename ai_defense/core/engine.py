from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..agents.command_classifier import CommandClassifierAgent
from ..agents.context_analyzer import ContextAnalyzerAgent
from ..agents.policy_enforcer import PolicyEnforcerAgent
from .alerts import AlertEngine
from .audit import AuditLogger
from .config import AppConfig
from .consensus import ConsensusEngine
from .llm_client import LLMClient
from .models import AgentDecision, FinalVerdict, SessionContext, Verdict
from .rule_engine import RuleEngine

log = logging.getLogger("ai_defense.engine")

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
        self._sessions: dict[str, SessionContext] = {}
        self._executor = ThreadPoolExecutor(max_workers=3)

    def create_session(self, username: str = "", role: str = "") -> SessionContext:
        session = SessionContext(username=username, role=role)
        self._sessions[session.session_id] = session
        self._audit.log_session_start(session)
        log.info("Session started: %s user=%s role=%s", session.session_id, username, role)
        return session

    def end_session(self, session: SessionContext) -> None:
        self._audit.log_session_end(session)
        self._sessions.pop(session.session_id, None)
        log.info("Session ended: %s (%d commands)", session.session_id, len(session.commands))

    def evaluate(self, command: str, session: SessionContext) -> FinalVerdict:
        t0 = time.perf_counter()

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
            if verdict.verdict == Verdict.DENY:
                self._alerts.notify(session, command, verdict)
            return verdict

        decisions: list[AgentDecision] = []
        futures = {}

        if self._classifier:
            futures[self._executor.submit(self._classifier.evaluate, command)] = "classifier"
        if self._context:
            futures[self._executor.submit(self._context.evaluate, command, session)] = "context"
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

        print(f"\n{CLR_SYSTEM}{'─' * 60}{CLR_RESET}")
        print(f"{CLR_SYSTEM}[AI] Команда: {CLR_BOLD}{command}{CLR_RESET}")

        for d in verdict.decisions:
            sc = _severity_color(d.severity.value)
            dv = d.verdict.value.upper()
            print(
                f"  {CLR_CYAN}├─ {d.agent_name}{CLR_RESET}: "
                f"{vc if d.verdict == verdict.verdict else CLR_DIM}{dv}{CLR_RESET} "
                f"({d.confidence:.0%}) {sc}[{d.severity.value}]{CLR_RESET} "
                f"{CLR_DIM}{d.reason}{CLR_RESET}"
            )
            if d.elapsed_ms:
                print(f"  {CLR_DIM}│  ⏱ {d.elapsed_ms:.0f}ms{CLR_RESET}")

        print(f"  {CLR_SYSTEM}└─ Итог: {vc}{CLR_BOLD}{v}{CLR_RESET} {CLR_DIM}({elapsed_ms:.0f}ms){CLR_RESET}")
        if verdict.reason:
            print(f"     {CLR_DIM}{verdict.reason}{CLR_RESET}")
        print(f"{CLR_SYSTEM}{'─' * 60}{CLR_RESET}")

    @property
    def audit(self) -> AuditLogger:
        return self._audit

    def close(self) -> None:
        self._executor.shutdown(wait=False)
        self._audit.close()
