from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import redis.asyncio as aioredis

from .config import get_settings

log = logging.getLogger("bastion.redis")

_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _pool
    if _pool is None:
        _pool = aioredis.from_url(
            get_settings().redis_url,
            decode_responses=True,
            max_connections=50,
        )
    return _pool


# ─── Command stream ──────────────────────────────────────────

COMMAND_STREAM = "stream:commands"
VERDICT_PREFIX = "verdict:"
SESSION_CONTROL_PREFIX = "session_control:"


async def publish_command(session_id: str, command: str, metadata: dict[str, Any] | None = None) -> str:
    """Push a command into the Redis stream for async validation.
    Returns the stream entry ID."""
    r = await get_redis()
    payload = {
        "session_id": session_id,
        "command": command,
        "metadata": json.dumps(metadata or {}),
    }
    entry_id = await r.xadd(COMMAND_STREAM, payload, maxlen=10000)
    return entry_id


async def wait_verdict(session_id: str, entry_id: str, timeout: float = 2.0) -> dict[str, Any]:
    """Wait for a verdict on a specific command.
    Falls back to DENY in strict mode if timeout."""
    r = await get_redis()
    key = f"{VERDICT_PREFIX}{session_id}:{entry_id}"
    raw = await r.blpop(key, timeout=timeout)
    if raw is None:
        settings = get_settings()
        if settings.strict_mode:
            return {"verdict": "deny", "reason": "Timeout — strict mode", "severity": "high"}
        return {"verdict": "allow", "reason": "Timeout — permissive fallback"}
    _, data = raw
    return json.loads(data)


async def publish_verdict(session_id: str, entry_id: str, verdict: dict[str, Any]) -> None:
    r = await get_redis()
    key = f"{VERDICT_PREFIX}{session_id}:{entry_id}"
    await r.rpush(key, json.dumps(verdict))
    await r.expire(key, 30)


# ─── Session control ─────────────────────────────────────────

async def send_session_control(session_id: str, action: str, reason: str = "") -> None:
    """Send KILL, FREEZE, or WARNING to a session."""
    r = await get_redis()
    channel = f"{SESSION_CONTROL_PREFIX}{session_id}"
    payload = json.dumps({"action": action.upper(), "reason": reason})
    await r.publish(channel, payload)
    log.info("Session control: %s -> %s (%s)", session_id, action, reason)


async def subscribe_session_control(session_id: str):
    """Async generator yielding control messages for a session."""
    r = await get_redis()
    pubsub = r.pubsub()
    channel = f"{SESSION_CONTROL_PREFIX}{session_id}"
    await pubsub.subscribe(channel)
    try:
        async for msg in pubsub.listen():
            if msg["type"] == "message":
                yield json.loads(msg["data"])
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
