"""4SSH-Ultimate — FastAPI Control Plane

WebSocket broadcasting, JWT auth, REST API for dashboard, VT integration,
and Redis stream consumer for command validation.
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .api.websocket import ws_manager
from .core.config import get_settings
from .core.database import get_db, get_engine
from .core.models import Alert, AuditLog, Role, Server, Session, User, VTScan
from .core.redis_client import (
    COMMAND_STREAM, get_redis, publish_verdict, send_session_control,
)
from .core.rule_engine import RuleEngine, RuleSet
from .core.schemas import (
    AlertOut, AuditLogOut, LoginRequest, ServerCreate, ServerOut,
    SessionControlRequest, SessionOut, StatsOut, TokenResponse, VTScanOut,
)
from .core.security import create_access_token, decode_access_token, verify_password
from .services.virustotal import VTScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("bastion.api")

security_scheme = HTTPBearer()
vt_scanner = VTScanner()


# ═══ Rule engine bootstrap ═══════════════════════════════════

def _build_rule_engine() -> RuleEngine:
    """Build rule engine with hardcoded critical rules.
    In production, these load from DB or config file."""
    import re
    rules = RuleSet(
        whitelist=["ls", "pwd", "whoami", "id", "hostname", "uptime", "date", "df", "du",
                   "ps", "top", "free", "uname", "cat", "head", "tail", "grep", "find",
                   "wc", "sort", "uniq", "awk", "less", "more", "echo", "env", "printenv",
                   "ip addr", "ip route", "ss", "netstat", "dig", "nslookup", "ping",
                   "traceroute", "w", "last", "history"],
        blacklist=[
            (re.compile(r"\brm\s+(?:.*\s)?-\w*r\w*f\w*\s+/(?:\s|$)"), "rm -rf / detected", "critical"),
            (re.compile(r"\brm\s+(?:.*\s)?-\w*r\w*f\w*\s+\*"), "rm -rf * detected", "critical"),
            (re.compile(r"\bdd\b.*\bof=/dev/"), "dd to block device", "critical"),
            (re.compile(r"\bmkfs\b"), "Filesystem formatting", "critical"),
            (re.compile(r":\(\)\s*\{.*\|.*&\s*\}"), "Fork bomb", "critical"),
            (re.compile(r"\b(?:wget|curl)\b.*\|\s*(?:ba)?sh"), "Download & execute", "critical"),
            (re.compile(r"/dev/tcp/"), "Reverse shell /dev/tcp", "critical"),
            (re.compile(r"\bhistory\s+-c\b"), "Стирание истории", "high"),
            (re.compile(r"\bbase64\b.*\|\s*(?:ba)?sh"), "Base64 decode & exec", "critical"),
            (re.compile(r"\beval\b.*\$\("), "Eval with substitution", "critical"),
            (re.compile(r"python[23]?\s+-c\s+.*(?:os\.system|subprocess|exec)"), "Python shell exec", "critical"),
            (re.compile(r"\bnc\b.*-[le]"), "Netcat listener", "high"),
            (re.compile(r"\biptables\s+-F\b"), "Firewall flush", "critical"),
            (re.compile(r"\bshutdown\b"), "System shutdown", "critical"),
            (re.compile(r"^\breboot\b"), "System reboot", "critical"),
            (re.compile(r"\bufw\s+disable\b"), "Firewall disable", "critical"),
            (re.compile(r"\bchmod\s+777\s+/"), "chmod 777 on system path", "high"),
            (re.compile(r"\bnohup\b.*&"), "Background persistent process", "high"),
            (re.compile(r"\bunset\s+HISTFILE\b"), "Отключение логирования", "high"),
            (re.compile(r"\bcrontab\s+-r\b"), "Удаление crontab", "high"),
        ],
        sensitive_paths=[
            ("/etc/shadow", "Файл паролей (shadow)", "critical", "deny"),
            ("/etc/sudoers", "Sudoers", "critical", "deny"),
            ("/etc/pam.d/", "PAM модули", "critical", "deny"),
            (".ssh/authorized_keys", "SSH ключи", "critical", "deny"),
            ("/etc/ld.so.preload", "LD preload", "critical", "deny"),
            ("/etc/passwd", "Файл пользователей", "high", "escalate"),
            ("/etc/hosts", "DNS hosts", "medium", "escalate"),
            ("/etc/crontab", "System crontab", "high", "escalate"),
        ],
        escalation_rules=[
            (re.compile(r"\bkill(?:all)?\s.*(?:\b1\b|sshd|systemd|init)"), "Kill critical process", "critical", "deny"),
            (re.compile(r"\bchmod\s+u\+s\b"), "SUID bit", "critical", "deny"),
            (re.compile(r"\bexport\s+LD_PRELOAD="), "LD_PRELOAD injection", "critical", "deny"),
            (re.compile(r"\balias\s+sudo="), "Alias sudo hijack", "critical", "deny"),
            (re.compile(r"\bmv\s+/(?:usr/)?s?bin/"), "Move system binary", "critical", "deny"),
            (re.compile(r"\bsystemctl\s+(?:stop|disable|mask)\b"), "Systemctl stop/disable", "high", "escalate"),
            (re.compile(r"\bssh\s+.*-[LRD]\b"), "SSH tunnel", "high", "escalate"),
            (re.compile(r"\bnmap\b"), "Network scanner", "high", "escalate"),
            (re.compile(r"\bstrace\b"), "Process tracing", "high", "escalate"),
            (re.compile(r"\btcpdump\b"), "Packet capture", "high", "escalate"),
            (re.compile(r"\b(?:ins|rm|mod)mod\b"), "Kernel module manipulation", "critical", "escalate"),
            (re.compile(r"\bmount\b"), "Mount operation", "high", "escalate"),
            (re.compile(r"\bdocker\s+(?:run|exec).*--privileged"), "Docker privileged", "critical", "escalate"),
            (re.compile(r"\buseradd\b"), "User creation", "high", "escalate"),
            (re.compile(r"\bchroot\b"), "Chroot", "high", "escalate"),
            (re.compile(r"\btee\s+/etc/"), "Write to /etc/ via tee", "high", "escalate"),
            (re.compile(r"\bwget\s+-O\b"), "Download to file", "medium", "escalate"),
            (re.compile(r"\bgcc\b.*-o\b"), "Compile binary", "medium", "escalate"),
        ],
        dangerous_content=[
            ("/dev/tcp/", "Reverse shell pattern", "critical"),
            ("ssh-rsa AAAA", "SSH public key injection", "high"),
            ("ALL=(ALL) NOPASSWD", "Sudoers NOPASSWD rule", "critical"),
            ("bash -i >&", "Interactive reverse shell", "critical"),
        ],
    )
    return RuleEngine(rules)


rule_engine = _build_rule_engine()


# ═══ Auth dependency ═════════════════════════════════════════

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or disabled")
    return user


# ═══ Lifespan ════════════════════════════════════════════════

async def _stream_consumer():
    """Background task: consume Redis command stream, validate, publish verdicts."""
    try:
        r = await get_redis()
        last_id = "0-0"
        log.info("Stream consumer started on '%s'", COMMAND_STREAM)
        while True:
            try:
                entries = await r.xread({COMMAND_STREAM: last_id}, count=10, block=1000)
                if not entries:
                    continue
                for stream_name, messages in entries:
                    for msg_id, fields in messages:
                        last_id = msg_id
                        session_id = fields.get("session_id", "")
                        command = fields.get("command", "")
                        result = rule_engine.evaluate(command)
                        if result:
                            verdict = {
                                "verdict": result.verdict,
                                "reason": result.reason,
                                "severity": result.severity,
                                "category": result.category,
                                "confidence": result.confidence,
                                "agent": result.agent,
                                "elapsed_ms": result.elapsed_ms,
                            }
                        else:
                            verdict = {"verdict": "allow", "reason": "No rule match — passed", "severity": "low"}

                        await publish_verdict(session_id, msg_id, verdict)

                        await ws_manager.broadcast("command_verdict", {
                            "session_id": session_id,
                            "command": command,
                            **verdict,
                        })
            except Exception as exc:
                log.error("Stream consumer error: %s", exc)
                await asyncio.sleep(1)
    except asyncio.CancelledError:
        log.info("Stream consumer stopped")


@asynccontextmanager
async def lifespan(app: FastAPI):
    consumer_task = asyncio.create_task(_stream_consumer())
    log.info("4SSH-Ultimate API started")
    yield
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    engine = get_engine()
    await engine.dispose()
    r = await get_redis()
    await r.close()
    log.info("4SSH-Ultimate API shutdown")


# ═══ App ═════════════════════════════════════════════════════

app = FastAPI(
    title="4SSH-Ultimate Control Plane",
    version="2.0.0",
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══ Auth routes ═════════════════════════════════════════════

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).where(User.username == body.username)
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    result2 = await db.execute(select(Role).where(Role.id == user.role_id))
    role = result2.scalar_one_or_none()
    role_name = role.name if role else "unknown"
    is_admin = role.is_admin if role else False

    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    token = create_access_token({"sub": user.username, "role": role_name})
    return TokenResponse(
        access_token=token, username=user.username, role=role_name, is_admin=is_admin,
    )


# ═══ Stats ═══════════════════════════════════════════════════

@app.get("/api/stats", response_model=StatsOut)
async def get_stats(db: AsyncSession = Depends(get_db), _user: User = Depends(get_current_user)):
    total_sess = (await db.execute(select(func.count(Session.id)))).scalar() or 0
    active_sess = (await db.execute(select(func.count(Session.id)).where(Session.status == "active"))).scalar() or 0
    total_cmds = (await db.execute(select(func.count(AuditLog.id)))).scalar() or 0
    total_denied = (await db.execute(select(func.count(AuditLog.id)).where(AuditLog.verdict == "deny"))).scalar() or 0
    total_esc = (await db.execute(select(func.count(AuditLog.id)).where(AuditLog.verdict == "escalate"))).scalar() or 0
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    unack = (await db.execute(select(func.count(Alert.id)).where(Alert.acknowledged == False))).scalar() or 0  # noqa: E712
    vt_total = (await db.execute(select(func.count(VTScan.id)))).scalar() or 0
    vt_mal = (await db.execute(select(func.count(VTScan.id)).where(VTScan.scan_status == "malicious"))).scalar() or 0
    return StatsOut(
        total_sessions=total_sess, active_sessions=active_sess, total_commands=total_cmds,
        total_denied=total_denied, total_escalated=total_esc, total_alerts=total_alerts,
        unack_alerts=unack, vt_scans_total=vt_total, vt_malicious=vt_mal,
    )


# ═══ Sessions ════════════════════════════════════════════════

@app.get("/api/sessions", response_model=list[SessionOut])
async def list_sessions(
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = select(Session).order_by(Session.started_at.desc()).limit(limit)
    if status_filter:
        q = q.where(Session.status == status_filter)
    result = await db.execute(q)
    sessions = result.scalars().all()
    return [SessionOut(id=str(s.id), username=s.username, role=s.role, server_profile=s.server_profile,
                       server_vendor=s.server_vendor, client_ip=str(s.client_ip) if s.client_ip else None,
                       status=s.status, command_count=s.command_count, threat_score=s.threat_score,
                       started_at=s.started_at, ended_at=s.ended_at) for s in sessions]


@app.post("/api/sessions/{session_id}/control")
async def control_session(
    session_id: str,
    body: SessionControlRequest,
    _user: User = Depends(get_current_user),
):
    await send_session_control(session_id, body.action, body.reason)
    await ws_manager.broadcast("session_control", {
        "session_id": session_id, "action": body.action, "reason": body.reason,
    })
    return {"status": "ok", "action": body.action, "session_id": session_id}


# ═══ Audit Logs ══════════════════════════════════════════════

@app.get("/api/logs", response_model=list[AuditLogOut])
async def list_logs(
    limit: int = Query(100, le=500),
    verdict: str | None = None,
    session_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if verdict:
        q = q.where(AuditLog.verdict == verdict)
    if session_id:
        q = q.where(AuditLog.session_id == session_id)
    result = await db.execute(q)
    logs = result.scalars().all()
    return [AuditLogOut(
        id=l.id, session_id=str(l.session_id) if l.session_id else None,
        username=l.username, role=l.role, command=l.command, verdict=l.verdict,
        reason=l.reason, severity=l.severity, category=l.category,
        is_escalated=l.is_escalated, admin_decision=l.admin_decision,
        server_profile=l.server_profile, server_vendor=l.server_vendor,
        elapsed_ms=l.elapsed_ms, created_at=l.created_at,
    ) for l in logs]


# ═══ Alerts ══════════════════════════════════════════════════

@app.get("/api/alerts", response_model=list[AlertOut])
async def list_alerts(
    limit: int = Query(50, le=200),
    unacknowledged: bool = False,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if unacknowledged:
        q = q.where(Alert.acknowledged == False)  # noqa: E712
    result = await db.execute(q)
    return [AlertOut(
        id=a.id, session_id=str(a.session_id) if a.session_id else None,
        alert_type=a.alert_type, severity=a.severity, title=a.title,
        detail=a.detail, acknowledged=a.acknowledged, created_at=a.created_at,
    ) for a in result.scalars().all()]


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    alert.acknowledged_by = user.id
    await db.commit()
    return {"status": "acknowledged"}


# ═══ Servers ═════════════════════════════════════════════════

@app.get("/api/servers", response_model=list[ServerOut])
async def list_servers(db: AsyncSession = Depends(get_db), _user: User = Depends(get_current_user)):
    result = await db.execute(select(Server).order_by(Server.hostname))
    return [ServerOut(
        id=s.id, hostname=s.hostname, ip_address=str(s.ip_address), port=s.port,
        server_type=s.server_type, vendor=s.vendor, description=s.description,
        tags=s.tags or [], is_active=s.is_active, health_status=s.health_status,
        last_health_check=s.last_health_check,
    ) for s in result.scalars().all()]


@app.post("/api/servers", response_model=ServerOut, status_code=201)
async def create_server(
    body: ServerCreate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    srv = Server(
        hostname=body.hostname, ip_address=body.ip_address, port=body.port,
        server_type=body.server_type, vendor=body.vendor, description=body.description,
        ssh_username=body.ssh_username, tags=body.tags,
    )
    db.add(srv)
    await db.commit()
    await db.refresh(srv)
    return ServerOut(
        id=srv.id, hostname=srv.hostname, ip_address=str(srv.ip_address), port=srv.port,
        server_type=srv.server_type, vendor=srv.vendor, description=srv.description,
        tags=srv.tags or [], is_active=srv.is_active, health_status=srv.health_status,
    )


# ═══ VT Scans ════════════════════════════════════════════════

@app.get("/api/vt-scans", response_model=list[VTScanOut])
async def list_vt_scans(
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(VTScan).order_by(VTScan.created_at.desc()).limit(limit))
    return [VTScanOut(
        id=s.id, session_id=str(s.session_id) if s.session_id else None,
        file_name=s.file_name, sha256=s.sha256, file_size=s.file_size,
        scan_status=s.scan_status, detection_count=s.detection_count,
        total_engines=s.total_engines, vt_link=s.vt_link,
        triggered_action=s.triggered_action, created_at=s.created_at,
    ) for s in result.scalars().all()]


# ═══ WebSocket ═══════════════════════════════════════════════

@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)
    except Exception:
        await ws_manager.disconnect(ws)
