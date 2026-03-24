from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

from .config import AuditConfig
from .models import FinalVerdict, SessionContext

log = logging.getLogger("ai_defense.audit")


class AuditLogger:
    """Persistent audit: SQLite + append-only JSONL for SIEM ingestion."""

    def __init__(self, cfg: AuditConfig) -> None:
        self._cfg = cfg
        self._db_path = Path(cfg.db_path)
        self._jsonl_path = Path(cfg.json_log)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL    NOT NULL,
                session_id  TEXT    NOT NULL,
                username    TEXT    NOT NULL DEFAULT '',
                role        TEXT    NOT NULL DEFAULT '',
                command     TEXT    NOT NULL,
                verdict     TEXT    NOT NULL,
                reason      TEXT    NOT NULL DEFAULT '',
                severity    TEXT    NOT NULL DEFAULT '',
                agents_json TEXT    NOT NULL DEFAULT '[]',
                escalated   INTEGER NOT NULL DEFAULT 0
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  TEXT PRIMARY KEY,
                username    TEXT NOT NULL DEFAULT '',
                role        TEXT NOT NULL DEFAULT '',
                start_time  REAL NOT NULL,
                end_time    REAL,
                cmd_count   INTEGER NOT NULL DEFAULT 0
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_log(verdict)")
        self._conn.commit()

    def log_decision(self, session: SessionContext, command: str, verdict: FinalVerdict) -> None:
        ts = time.time()

        agents_data = []
        max_severity = "low"
        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        for d in verdict.decisions:
            agents_data.append({
                "agent": d.agent_name,
                "verdict": d.verdict.value,
                "confidence": d.confidence,
                "category": d.category.value,
                "reason": d.reason,
                "severity": d.severity.value,
                "elapsed_ms": d.elapsed_ms,
            })
            if sev_order.get(d.severity.value, 0) > sev_order.get(max_severity, 0):
                max_severity = d.severity.value

        agents_json = json.dumps(agents_data, ensure_ascii=False)

        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO audit_log (timestamp, session_id, username, role, command, verdict, reason, severity, agents_json, escalated) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ts, session.session_id, session.username, session.role,
                     command, verdict.verdict.value, verdict.reason, max_severity,
                     agents_json, int(verdict.escalated)),
                )
                self._conn.commit()
        except Exception as exc:
            log.error("SQLite write error: %s", exc)

        jsonl_record = {
            "@timestamp": ts,
            "session_id": session.session_id,
            "username": session.username,
            "role": session.role,
            "command": command,
            "verdict": verdict.verdict.value,
            "reason": verdict.reason,
            "severity": max_severity,
            "escalated": verdict.escalated,
            "agents": agents_data,
        }
        try:
            with open(self._jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(jsonl_record, ensure_ascii=False) + "\n")
        except Exception as exc:
            log.error("JSONL write error: %s", exc)

    def log_session_start(self, session: SessionContext) -> None:
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO sessions (session_id, username, role, start_time, cmd_count) VALUES (?, ?, ?, ?, 0)",
                    (session.session_id, session.username, session.role, session.start_time),
                )
                self._conn.commit()
        except Exception as exc:
            log.error("Session start log error: %s", exc)

    def log_session_end(self, session: SessionContext) -> None:
        try:
            with self._lock:
                self._conn.execute(
                    "UPDATE sessions SET end_time = ?, cmd_count = ? WHERE session_id = ?",
                    (time.time(), len(session.commands), session.session_id),
                )
                self._conn.commit()
        except Exception as exc:
            log.error("Session end log error: %s", exc)

    def get_recent_logs(self, limit: int = 100) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT timestamp, session_id, username, role, command, verdict, reason, severity, escalated "
                "FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            cols = ["timestamp", "session_id", "username", "role", "command", "verdict", "reason", "severity", "escalated"]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_stats(self) -> dict:
        with self._lock:
            cur = self._conn.execute("SELECT verdict, COUNT(*) FROM audit_log GROUP BY verdict")
            verdicts = dict(cur.fetchall())
            cur2 = self._conn.execute("SELECT COUNT(*) FROM audit_log")
            total = cur2.fetchone()[0]
            cur3 = self._conn.execute("SELECT COUNT(*) FROM sessions")
            sessions = cur3.fetchone()[0]
            cur4 = self._conn.execute("SELECT COUNT(*) FROM audit_log WHERE severity IN ('high', 'critical')")
            high_sev = cur4.fetchone()[0]
        return {
            "total_commands": total,
            "total_sessions": sessions,
            "verdicts": verdicts,
            "high_severity_count": high_sev,
        }

    def get_session_logs(self, session_id: str) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT timestamp, command, verdict, reason, severity, agents_json "
                "FROM audit_log WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            )
            cols = ["timestamp", "command", "verdict", "reason", "severity", "agents_json"]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def cleanup_old_records(self) -> int:
        """Delete audit records older than retention_days. Returns number of deleted rows."""
        days = self._cfg.retention_days
        if not days or days <= 0:
            return 0
        cutoff = time.time() - days * 86400
        try:
            with self._lock:
                cur = self._conn.execute(
                    "DELETE FROM audit_log WHERE timestamp < ?", (cutoff,),
                )
                self._conn.execute(
                    "DELETE FROM sessions WHERE end_time IS NOT NULL AND end_time < ?",
                    (cutoff,),
                )
                self._conn.commit()
                deleted = cur.rowcount
            if deleted:
                log.info("Retention cleanup: removed %d records older than %d days", deleted, days)
            return deleted
        except Exception as exc:
            log.error("Retention cleanup error: %s", exc)
            return 0

    def close(self) -> None:
        if self._conn:
            self._conn.close()
