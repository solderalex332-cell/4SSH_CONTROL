from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from ..core.audit import AuditLogger


def _html_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def create_app(audit: AuditLogger) -> FastAPI:
    app = FastAPI(title="4SSH_CONTROL Dashboard", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return _render_dashboard(audit)

    @app.get("/api/stats")
    async def api_stats():
        return audit.get_stats()

    @app.get("/api/logs")
    async def api_logs(limit: int = 100):
        return audit.get_recent_logs(limit)

    @app.get("/api/session/{session_id}")
    async def api_session(session_id: str):
        return audit.get_session_logs(session_id)

    return app


def _render_dashboard(audit: AuditLogger) -> str:
    stats = audit.get_stats()
    logs = audit.get_recent_logs(50)

    total = stats.get("total_commands", 0)
    verdicts = stats.get("verdicts", {})
    allow_count = verdicts.get("allow", 0)
    deny_count = verdicts.get("deny", 0)
    escalate_count = verdicts.get("escalate", 0)
    high_sev = stats.get("high_severity_count", 0)
    sessions = stats.get("total_sessions", 0)

    log_rows = ""
    for entry in logs:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry["timestamp"]))
        v = entry["verdict"]
        vc = {"allow": "#22c55e", "deny": "#ef4444", "escalate": "#eab308"}.get(v, "#888")
        sev = entry.get("severity", "")
        sc = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}.get(sev, "#888")
        escalated = entry.get("escalated")
        if escalated:
            esc_label = f' <span style="color:#eab308;font-size:0.65rem;">⚡ эскалация</span>'
        else:
            esc_label = ""
        cmd_escaped = _html_escape(str(entry["command"]))
        reason_escaped = _html_escape(str(entry.get("reason", "")))
        username_escaped = _html_escape(str(entry.get("username", "")))

        log_rows += f"""
        <tr>
            <td class="ts">{ts}</td>
            <td>{str(entry.get('session_id', ''))[:8]}</td>
            <td>{username_escaped}</td>
            <td><code>{cmd_escaped}</code></td>
            <td><span class="badge" style="background:{vc}">{v.upper()}</span>{esc_label}</td>
            <td><span class="badge-sm" style="background:{sc}">{sev}</span></td>
            <td class="reason">{reason_escaped}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>4SSH_CONTROL — AI Defense Dashboard</title>
<style>
  :root {{
    --bg: #0f172a; --card: #1e293b; --border: #334155;
    --text: #e2e8f0; --dim: #94a3b8; --accent: #38bdf8;
    --green: #22c55e; --red: #ef4444; --yellow: #eab308; --orange: #f97316;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; background:var(--bg); color:var(--text); padding:24px; }}
  h1 {{ font-size:1.5rem; margin-bottom:8px; color:var(--accent); }}
  .subtitle {{ color:var(--dim); margin-bottom:24px; font-size:0.85rem; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:32px; }}
  .card {{
    background:var(--card); border:1px solid var(--border); border-radius:12px;
    padding:20px; text-align:center;
  }}
  .card .num {{ font-size:2rem; font-weight:700; }}
  .card .label {{ color:var(--dim); font-size:0.75rem; text-transform:uppercase; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.8rem; table-layout:fixed; }}
  th {{ text-align:left; color:var(--dim); padding:10px 8px; border-bottom:2px solid var(--border); font-size:0.7rem; text-transform:uppercase; }}
  td {{ padding:8px; border-bottom:1px solid var(--border); vertical-align:top; word-wrap:break-word; overflow-wrap:break-word; }}
  tr:hover {{ background:rgba(56,189,248,0.05); }}
  .ts {{ color:var(--dim); white-space:nowrap; font-size:0.75rem; }}
  .col-ts {{ width:130px; }}
  .col-sess {{ width:70px; }}
  .col-user {{ width:80px; }}
  .col-cmd {{ width:25%; }}
  .col-verdict {{ width:110px; }}
  .col-sev {{ width:70px; }}
  .col-reason {{ }}
  code {{ background:rgba(56,189,248,0.1); padding:2px 6px; border-radius:4px; font-size:0.8rem; word-break:break-all; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:999px; color:#fff; font-size:0.7rem; font-weight:600; white-space:nowrap; }}
  .badge-sm {{ display:inline-block; padding:1px 6px; border-radius:999px; color:#fff; font-size:0.65rem; }}
  .reason {{ color:var(--dim); font-size:0.75rem; }}
  .refresh {{ color:var(--accent); text-decoration:none; font-size:0.8rem; }}
  .header {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>4SSH_CONTROL — Multi-Agent AI Defense</h1>
    <div class="subtitle">Дашборд мониторинга SSH-бастиона в реальном времени</div>
  </div>
  <a href="/" class="refresh">↻ Обновить</a>
</div>

<div class="grid">
  <div class="card"><div class="num">{total}</div><div class="label">Всего команд</div></div>
  <div class="card"><div class="num" style="color:var(--green)">{allow_count}</div><div class="label">Разрешено</div></div>
  <div class="card"><div class="num" style="color:var(--red)">{deny_count}</div><div class="label">Заблокировано</div></div>
  <div class="card"><div class="num" style="color:var(--yellow)">{escalate_count}</div><div class="label">Эскалации</div></div>
  <div class="card"><div class="num" style="color:var(--orange)">{high_sev}</div><div class="label">High/Critical</div></div>
  <div class="card"><div class="num" style="color:var(--accent)">{sessions}</div><div class="label">Сессий</div></div>
</div>

<h2 style="font-size:1.1rem;margin-bottom:12px;">Последние события</h2>
<div style="overflow-x:auto;">
<table>
  <thead><tr>
    <th class="col-ts">Время</th><th class="col-sess">Сессия</th><th class="col-user">Пользователь</th><th class="col-cmd">Команда</th><th class="col-verdict">Вердикт</th><th class="col-sev">Severity</th><th class="col-reason">Причина</th>
  </tr></thead>
  <tbody>{log_rows if log_rows else '<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:40px;">Нет данных</td></tr>'}</tbody>
</table>
</div>

<script>setTimeout(()=>location.reload(), 15000);</script>
</body>
</html>"""
