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
class SensitivePath:
    pattern: str
    reason: str
    severity: str = "high"
    action: str = "escalate"     # deny | escalate


@dataclass
class DangerousContent:
    pattern: str
    reason: str
    severity: str = "high"


@dataclass
class EscalationRule:
    pattern: str
    reason: str
    severity: str = "high"
    action: str = "escalate"     # escalate | deny


@dataclass
class RulesConfig:
    whitelist: list[str] = field(default_factory=list)
    blacklist: list[BlacklistRule] = field(default_factory=list)
    sensitive_paths: list[SensitivePath] = field(default_factory=list)
    dangerous_content: list[DangerousContent] = field(default_factory=list)
    escalation_rules: list[EscalationRule] = field(default_factory=list)


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
class NetworkProfileRules:
    safe_commands: list[str] = field(default_factory=list)
    dangerous_patterns: list[BlacklistRule] = field(default_factory=list)
    critical_patterns: list[BlacklistRule] = field(default_factory=list)
    escalation_patterns: list[EscalationRule] = field(default_factory=list)


@dataclass
class TargetProfile:
    type: str = "linux"                     # linux | network
    vendor: str = ""                        # cisco_ios | cisco_nxos | junos | mikrotik | huawei_vrp | arista_eos | generic_network
    detect_banner: list[str] = field(default_factory=list)
    detect_prompt: list[str] = field(default_factory=list)
    context_command: str = ""               # e.g. "show running-config"
    context_max_bytes: int = 8192
    network_rules: NetworkProfileRules = field(default_factory=NetworkProfileRules)


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
    target_profiles: dict[str, TargetProfile] = field(default_factory=dict)


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
    sp_raw = rules_raw.get("sensitive_paths", [])
    sensitive_paths = [SensitivePath(**item) if isinstance(item, dict) else SensitivePath(pattern=str(item), reason="") for item in sp_raw]
    dc_raw = rules_raw.get("dangerous_content", [])
    dangerous_content = [DangerousContent(**item) if isinstance(item, dict) else DangerousContent(pattern=str(item), reason="") for item in dc_raw]
    er_raw = rules_raw.get("escalation_rules", [])
    escalation_rules = [EscalationRule(**item) if isinstance(item, dict) else EscalationRule(pattern=str(item), reason="") for item in er_raw]
    rules = RulesConfig(
        whitelist=rules_raw.get("whitelist", []),
        blacklist=blacklist,
        sensitive_paths=sensitive_paths,
        dangerous_content=dangerous_content,
        escalation_rules=escalation_rules,
    )

    rbac_raw = raw.get("rbac", {})
    roles = {}
    for rname, rvals in rbac_raw.get("roles", {}).items():
        roles[rname] = _build_dataclass(RolePolicy, rvals)
    users = {}
    for uname, uvals in rbac_raw.get("users", {}).items():
        users[uname] = _build_dataclass(UserMapping, uvals)
    tp_raw = rbac_raw.get("time_policy", {})
    if "high_risk_hours" in tp_raw:
        tp_raw = tp_raw["high_risk_hours"]
    tp = _build_dataclass(TimePolicy, tp_raw)
    rbac = RBACConfig(roles=roles, users=users, time_policy=tp)

    alerts_raw = raw.get("alerts", {})
    alerts = AlertsConfig(
        telegram=_build_dataclass(TelegramConfig, alerts_raw.get("telegram")),
        webhook=_build_dataclass(WebhookConfig, alerts_raw.get("webhook")),
    )

    audit = _build_dataclass(AuditConfig, raw.get("audit"))
    dashboard = _build_dataclass(DashboardConfig, raw.get("dashboard"))
    bastion = _build_dataclass(BastionConfig, raw.get("bastion"))

    tp_raw = raw.get("target_profiles", {})
    target_profiles: dict[str, TargetProfile] = {}
    for pname, pvals in tp_raw.items():
        if not isinstance(pvals, dict):
            continue
        pvals = dict(pvals)
        nr_raw = pvals.pop("network_rules", {})
        nr = NetworkProfileRules()
        if isinstance(nr_raw, dict):
            nr.safe_commands = nr_raw.get("safe_commands", [])
            nr.dangerous_patterns = [
                BlacklistRule(**item) if isinstance(item, dict) else BlacklistRule(pattern=str(item), reason="")
                for item in nr_raw.get("dangerous_patterns", [])
            ]
            nr.critical_patterns = [
                BlacklistRule(**item) if isinstance(item, dict) else BlacklistRule(pattern=str(item), reason="")
                for item in nr_raw.get("critical_patterns", [])
            ]
            nr.escalation_patterns = [
                EscalationRule(**item) if isinstance(item, dict) else EscalationRule(pattern=str(item), reason="")
                for item in nr_raw.get("escalation_patterns", [])
            ]
        profile = _build_dataclass(TargetProfile, pvals)
        profile.network_rules = nr
        target_profiles[pname] = profile

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
        target_profiles=target_profiles,
    )
