"""Pydantic schemas for API request/response validation."""
from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    is_admin: bool


class UserOut(BaseModel):
    id: int
    username: str
    role: str | None = None
    is_active: bool
    last_login: datetime | None = None

    class Config:
        from_attributes = True


class ServerOut(BaseModel):
    id: int
    hostname: str
    ip_address: str
    port: int
    server_type: str
    vendor: str
    description: str
    tags: list[str]
    is_active: bool
    health_status: str
    last_health_check: datetime | None = None

    class Config:
        from_attributes = True


class ServerCreate(BaseModel):
    hostname: str
    ip_address: str
    port: int = 22
    server_type: str = "linux"
    vendor: str = ""
    description: str = ""
    ssh_username: str = ""
    tags: list[str] = []


class SessionOut(BaseModel):
    id: str
    username: str
    role: str
    server_profile: str
    server_vendor: str
    client_ip: str | None = None
    status: str
    command_count: int
    threat_score: float
    started_at: datetime
    ended_at: datetime | None = None

    class Config:
        from_attributes = True


class AuditLogOut(BaseModel):
    id: int
    session_id: str | None = None
    username: str
    role: str
    command: str
    verdict: str
    reason: str
    severity: str
    category: str
    is_escalated: bool
    admin_decision: str | None = None
    server_profile: str
    server_vendor: str
    elapsed_ms: float
    created_at: datetime

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: int
    session_id: str | None = None
    alert_type: str
    severity: str
    title: str
    detail: str
    acknowledged: bool
    created_at: datetime

    class Config:
        from_attributes = True


class VTScanOut(BaseModel):
    id: int
    session_id: str | None = None
    file_name: str
    sha256: str
    file_size: int
    scan_status: str
    detection_count: int
    total_engines: int
    vt_link: str | None = None
    triggered_action: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class StatsOut(BaseModel):
    total_sessions: int = 0
    active_sessions: int = 0
    total_commands: int = 0
    total_denied: int = 0
    total_escalated: int = 0
    total_alerts: int = 0
    unack_alerts: int = 0
    vt_scans_total: int = 0
    vt_malicious: int = 0


class SessionControlRequest(BaseModel):
    action: str = Field(..., pattern="^(KILL|FREEZE|WARNING)$")
    reason: str = ""
