from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CommandCategory(str, Enum):
    SAFE = "safe"
    RISKY = "risky"
    DESTRUCTIVE = "destructive"
    RECON = "recon"
    EXFIL = "exfil"
    PRIVILEGE_ESCALATION = "privesc"
    CONFIG_CHANGE = "config_change"
    UNKNOWN = "unknown"


@dataclass
class AgentDecision:
    agent_name: str
    verdict: Verdict
    confidence: float              # 0.0 – 1.0
    category: CommandCategory = CommandCategory.UNKNOWN
    reason: str = ""
    severity: Severity = Severity.LOW
    elapsed_ms: float = 0.0


@dataclass
class FinalVerdict:
    verdict: Verdict
    decisions: list[AgentDecision] = field(default_factory=list)
    reason: str = ""
    escalated: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class SessionCommand:
    command: str
    output: str = ""
    timestamp: float = field(default_factory=time.time)
    verdict: Verdict | None = None


@dataclass
class SessionContext:
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    username: str = ""
    role: str = ""
    target_profile: str = ""
    target_vendor: str = ""
    commands: list[SessionCommand] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    network_context: str = ""

    def add_command(self, cmd: str, verdict: Verdict | None = None) -> SessionCommand:
        entry = SessionCommand(command=cmd, verdict=verdict)
        self.commands.append(entry)
        return entry

    def recent_commands(self, n: int = 20) -> list[SessionCommand]:
        return self.commands[-n:]

    def command_history_text(self, n: int = 20) -> str:
        lines = []
        for sc in self.recent_commands(n):
            tag = sc.verdict.value if sc.verdict else "pending"
            lines.append(f"[{tag}] {sc.command}")
        return "\n".join(lines)
