from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.1
    timeout: int = 10

    def resolve_api_key(self) -> str:
        return self.api_key or os.environ.get("OPENAI_API_KEY", "")

    def resolve_base_url(self) -> str | None:
        return self.base_url or None


@dataclass
class AgentToggle:
    enabled: bool = True
    weight: float = 1.0
    max_history: int = 50


@dataclass
class ConsensusConfig:
    strategy: str = "weighted_majority"
    deny_threshold: float = 0.5
    escalate_on_disagreement: bool = True


@dataclass
class BlacklistRule:
    pattern: str
    reason: str
    severity: str = "high"


@dataclass
class RulesConfig:
    whitelist: list[str] = field(default_factory=list)
    blacklist: list[BlacklistRule] = field(default_factory=list)


@dataclass
class RolePolicy:
    description: str = ""
    allowed_commands: list[str] = field(default_factory=list)
    denied_commands: list[str] = field(default_factory=list)


@dataclass
class UserMapping:
    role: str = "dev"


@dataclass
class TimePolicy:
    start: str = "22:00"
    end: str = "06:00"
    timezone: str = "Europe/Moscow"
    action: str = "escalate"


@dataclass
class RBACConfig:
    roles: dict[str, RolePolicy] = field(default_factory=dict)
    users: dict[str, UserMapping] = field(default_factory=dict)
    time_policy: TimePolicy = field(default_factory=TimePolicy)


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AlertsConfig:
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)


@dataclass
class AuditConfig:
    db_path: str = "audit.db"
    json_log: str = "audit.jsonl"
    retention_days: int = 90


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8080


@dataclass
class BastionConfig:
    listen_port: int = 2222
    target_host: str = ""
    target_port: int = 22
    target_user: str = ""
    target_password: str = ""


@dataclass
class AppConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    agents: dict[str, AgentToggle] = field(default_factory=dict)
    consensus: ConsensusConfig = field(default_factory=ConsensusConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    rbac: RBACConfig = field(default_factory=RBACConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    bastion: BastionConfig = field(default_factory=BastionConfig)


def _build_dataclass(cls: type, data: dict[str, Any] | None):
    if data is None:
        return cls()
    filtered = {}
    for f_name in cls.__dataclass_fields__:
        if f_name in data:
            filtered[f_name] = data[f_name]
    return cls(**filtered)


def load_config(path: str | Path = "config.yaml") -> AppConfig:
    path = Path(path)
    if not path.exists():
        return AppConfig()

    with open(path, encoding="utf-8") as fh:
        raw: dict = yaml.safe_load(fh) or {}

    llm = _build_dataclass(LLMConfig, raw.get("llm"))

    agents_raw = raw.get("agents", {})
    agents = {}
    for name, vals in agents_raw.items():
        agents[name] = _build_dataclass(AgentToggle, vals)

    consensus = _build_dataclass(ConsensusConfig, raw.get("consensus"))

    rules_raw = raw.get("rules", {})
    bl_raw = rules_raw.get("blacklist", [])
    blacklist = [BlacklistRule(**item) if isinstance(item, dict) else BlacklistRule(pattern=str(item), reason="") for item in bl_raw]
    rules = RulesConfig(
        whitelist=rules_raw.get("whitelist", []),
        blacklist=blacklist,
    )

    rbac_raw = raw.get("rbac", {})
    roles = {}
    for rname, rvals in rbac_raw.get("roles", {}).items():
        roles[rname] = _build_dataclass(RolePolicy, rvals)
    users = {}
    for uname, uvals in rbac_raw.get("users", {}).items():
        users[uname] = _build_dataclass(UserMapping, uvals)
    tp = _build_dataclass(TimePolicy, rbac_raw.get("time_policy"))
    rbac = RBACConfig(roles=roles, users=users, time_policy=tp)

    alerts_raw = raw.get("alerts", {})
    alerts = AlertsConfig(
        telegram=_build_dataclass(TelegramConfig, alerts_raw.get("telegram")),
        webhook=_build_dataclass(WebhookConfig, alerts_raw.get("webhook")),
    )

    audit = _build_dataclass(AuditConfig, raw.get("audit"))
    dashboard = _build_dataclass(DashboardConfig, raw.get("dashboard"))
    bastion = _build_dataclass(BastionConfig, raw.get("bastion"))

    return AppConfig(
        llm=llm,
        agents=agents,
        consensus=consensus,
        rules=rules,
        rbac=rbac,
        alerts=alerts,
        audit=audit,
        dashboard=dashboard,
        bastion=bastion,
    )
