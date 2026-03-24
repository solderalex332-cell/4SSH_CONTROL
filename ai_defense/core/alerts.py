from __future__ import annotations

import json
import logging
import urllib.request

from .config import AlertsConfig
from .models import FinalVerdict, SessionContext

log = logging.getLogger("ai_defense.alerts")

SEVERITY_EMOJI = {
    "low": "\u2705",
    "medium": "\u26a0\ufe0f",
    "high": "\ud83d\udea8",
    "critical": "\ud83d\udd34",
}


def _max_severity(verdict: FinalVerdict) -> str:
    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    best = "low"
    for d in verdict.decisions:
        if sev_order.get(d.severity.value, 0) > sev_order.get(best, 0):
            best = d.severity.value
    return best


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class AlertEngine:
    """Sends alerts via Telegram and/or webhook on deny/escalate events."""

    def __init__(self, cfg: AlertsConfig) -> None:
        self._cfg = cfg

    def notify(self, session: SessionContext, command: str, verdict: FinalVerdict) -> None:
        if verdict.verdict.value == "allow":
            return

        sev = _max_severity(verdict)
        emoji = SEVERITY_EMOJI.get(sev, "")

        reasons = []
        for d in verdict.decisions:
            if d.reason:
                reasons.append(f"  • {_escape_html(d.agent_name)}: {_escape_html(d.reason)}")

        text = (
            f"{emoji} <b>SSH Bastion Alert</b>\n"
            f"<b>Verdict:</b> {_escape_html(verdict.verdict.value.upper())}\n"
            f"<b>Severity:</b> {_escape_html(sev)}\n"
            f"<b>Session:</b> {_escape_html(session.session_id)}\n"
            f"<b>User:</b> {_escape_html(session.username)} ({_escape_html(session.role)})\n"
            f"<b>Command:</b> <code>{_escape_html(command)}</code>\n"
            f"<b>Reason:</b> {_escape_html(verdict.reason)}\n"
        )
        if reasons:
            text += "<b>Agent details:</b>\n" + "\n".join(reasons) + "\n"

        if self._cfg.telegram.enabled:
            self._send_telegram(text)

        if self._cfg.webhook.enabled:
            self._send_webhook(session, command, verdict, sev)

    def _send_telegram(self, text: str) -> None:
        tg = self._cfg.telegram
        if not tg.bot_token or not tg.chat_id:
            return
        url = f"https://api.telegram.org/bot{tg.bot_token}/sendMessage"
        payload = json.dumps({"chat_id": tg.chat_id, "text": text, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            log.error("Telegram send failed: %s", exc)

    def _send_webhook(self, session: SessionContext, command: str, verdict: FinalVerdict, sev: str) -> None:
        wh = self._cfg.webhook
        if not wh.url:
            return
        body = {
            "event": "ssh_bastion_alert",
            "verdict": verdict.verdict.value,
            "severity": sev,
            "session_id": session.session_id,
            "username": session.username,
            "role": session.role,
            "command": command,
            "reason": verdict.reason,
            "escalated": verdict.escalated,
            "agents": [
                {"name": d.agent_name, "verdict": d.verdict.value, "reason": d.reason}
                for d in verdict.decisions
            ],
        }
        payload = json.dumps(body, ensure_ascii=False).encode()
        headers = dict(wh.headers)
        headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(wh.url, data=payload, headers=headers)
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            log.error("Webhook send failed: %s", exc)
