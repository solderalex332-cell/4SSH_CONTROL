from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ═══ Enums ═══════════════════════════════════════════════════

class VerdictType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class SeverityType(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    KILLED = "killed"
    FROZEN = "frozen"
    ERROR = "error"


class ServerType(str, Enum):
    LINUX = "linux"
    CISCO_IOS = "cisco_ios"
    JUNOS = "junos"
    MIKROTIK = "mikrotik"
    HUAWEI_VRP = "huawei_vrp"
    ARISTA_EOS = "arista_eos"
    GENERIC_NETWORK = "generic_network"


class ScanStatus(str, Enum):
    PENDING = "pending"
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    ERROR = "error"


class AlertType(str, Enum):
    COMMAND_DENY = "command_deny"
    COMMAND_ESCALATE = "command_escalate"
    FILE_MALICIOUS = "file_malicious"
    SESSION_KILL = "session_kill"
    RATE_LIMIT = "rate_limit"
    INTRUSION = "intrusion"


# ═══ ORM Models ══════════════════════════════════════════════

class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    allowed_commands = Column(ARRAY(Text), default=[])
    denied_commands = Column(ARRAY(Text), default=[])
    is_admin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role_id: Mapped[int | None] = mapped_column(ForeignKey("roles.id", ondelete="SET NULL"))
    is_active: Mapped[bool] = mapped_column(default=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    role: Mapped[Role | None] = relationship(back_populates="users")


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(256))
    ip_address = Column(INET, nullable=False)
    port: Mapped[int] = mapped_column(default=22)
    server_type: Mapped[str] = mapped_column(String(32), default="linux")
    vendor: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    ssh_username: Mapped[str] = mapped_column(String(128), default="")
    ssh_key_path: Mapped[str | None] = mapped_column(Text)
    tags = Column(ARRAY(Text), default=[])
    is_active: Mapped[bool] = mapped_column(default=True)
    health_status: Mapped[str] = mapped_column(String(32), default="unknown")
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id"))
    username: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(64), default="")
    server_profile: Mapped[str] = mapped_column(String(32), default="linux")
    server_vendor: Mapped[str] = mapped_column(String(64), default="")
    client_ip = Column(INET)
    status: Mapped[str] = mapped_column(String(16), default="active")
    command_count: Mapped[int] = mapped_column(default=0)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    network_context: Mapped[str | None] = mapped_column(Text)

    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="session")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"))
    username: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(64), default="")
    command: Mapped[str] = mapped_column(Text)
    sanitized_cmd: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="low")
    category: Mapped[str] = mapped_column(String(32), default="unknown")
    is_escalated: Mapped[bool] = mapped_column(default=False)
    admin_decision: Mapped[str | None] = mapped_column(String(16))
    agent_decisions = Column(JSONB, default=[])
    server_profile: Mapped[str] = mapped_column(String(32), default="linux")
    server_vendor: Mapped[str] = mapped_column(String(64), default="")
    elapsed_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    session: Mapped[Session | None] = relationship(back_populates="audit_logs")


class VTScan(Base):
    __tablename__ = "vt_scans"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"))
    file_name: Mapped[str] = mapped_column(Text)
    file_path: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(BigInteger, default=0)
    scan_status: Mapped[str] = mapped_column(String(16), default="pending")
    detection_count: Mapped[int] = mapped_column(default=0)
    total_engines: Mapped[int] = mapped_column(default=0)
    vt_link: Mapped[str | None] = mapped_column(Text)
    raw_result = Column(JSONB)
    triggered_action: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"))
    alert_type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), default="high")
    title: Mapped[str] = mapped_column(Text)
    detail: Mapped[str] = mapped_column(Text, default="")
    acknowledged: Mapped[bool] = mapped_column(default=False)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
