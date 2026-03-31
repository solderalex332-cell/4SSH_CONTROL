"""4SSH-Ultimate Async SSH Bastion

Intercepts SSH sessions, buffers keystrokes, validates commands via Redis,
listens for session control signals (KILL/FREEZE/WARNING).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
import sys
import time
from typing import Any

import paramiko

from .core.config import get_settings
from .core.redis_client import (
    get_redis, publish_command, subscribe_session_control, wait_verdict,
)

logging.basicConfig(
    level=logging.INFO,
    format="\033[90m%(asctime)s [%(name)s] %(message)s\033[0m",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bastion")

CLR = {
    "reset": "\033[0m", "bold": "\033[1m", "cyan": "\033[96m",
    "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
    "dim": "\033[90m", "mag": "\033[95m",
}


class GatewayServer(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.username: str = ""

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(self, channel, term, width, height, px_w, px_h, modes) -> bool:
        return True


async def _read_channel(chan: paramiko.Channel, timeout: float = 0.05) -> bytes:
    """Non-blocking channel read via asyncio."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: chan.recv(4096) if chan.recv_ready() else b"")


async def _bridge_target_to_admin(
    target_chan: paramiko.Channel,
    admin_chan: paramiko.Channel,
    session_id: str,
):
    """Forward target output to admin channel."""
    try:
        while not target_chan.closed:
            data = await _read_channel(target_chan)
            if data:
                admin_chan.sendall(data)
            else:
                await asyncio.sleep(0.02)
    except Exception as e:
        log.debug("Bridge stopped: %s", e)


async def _control_listener(
    session_id: str,
    admin_chan: paramiko.Channel,
    target_chan: paramiko.Channel,
    state: dict,
):
    """Listen for KILL/FREEZE/WARNING on Redis pubsub."""
    try:
        async for msg in subscribe_session_control(session_id):
            action = msg.get("action", "")
            reason = msg.get("reason", "")
            log.info("Control signal for %s: %s (%s)", session_id, action, reason)

            if action == "KILL":
                notice = f"\r\n\033[91m[SYSTEM] Session terminated: {reason}\033[0m\r\n"
                admin_chan.sendall(notice.encode())
                state["killed"] = True
                admin_chan.close()
                target_chan.close()
                return

            elif action == "FREEZE":
                state["frozen"] = True
                notice = f"\r\n\033[93m[SYSTEM] Session frozen: {reason}\033[0m\r\n"
                admin_chan.sendall(notice.encode())

            elif action == "WARNING":
                notice = f"\r\n\033[93m[WARNING] {reason}\033[0m\r\n"
                admin_chan.sendall(notice.encode())
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.warning("Control listener error: %s", e)


async def handle_session(
    admin_chan: paramiko.Channel,
    gateway: GatewayServer,
    target_host: str,
    target_port: int,
    target_user: str,
    target_pass: str,
) -> None:
    """Main session handler: intercept commands, validate via Redis, bridge I/O."""
    import uuid
    session_id = uuid.uuid4().hex[:12]
    username = gateway.username or "unknown"

    log.info("Session %s started for user '%s' -> %s:%d", session_id, username, target_host, target_port)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    state = {"frozen": False, "killed": False}

    try:
        ssh.connect(target_host, target_port, target_user, target_pass, timeout=10)
        target_chan = ssh.invoke_shell()

        await asyncio.sleep(0.5)
        initial = await _read_channel(target_chan, 1.0)
        if initial:
            admin_chan.sendall(initial)

        bridge_task = asyncio.create_task(
            _bridge_target_to_admin(target_chan, admin_chan, session_id)
        )
        control_task = asyncio.create_task(
            _control_listener(session_id, admin_chan, target_chan, state)
        )

        cmd_buffer: list[bytes] = []
        loop = asyncio.get_event_loop()

        while not admin_chan.closed and not state["killed"]:
            char = await loop.run_in_executor(
                None, lambda: admin_chan.recv(1) if admin_chan.recv_ready() else b""
            )
            if not char:
                await asyncio.sleep(0.01)
                continue

            if state["frozen"]:
                admin_chan.sendall(b"\r\n\033[93m[FROZEN] Input blocked\033[0m\r\n")
                continue

            if char in (b"\r", b"\n"):
                full_cmd = b"".join(cmd_buffer).decode("utf-8", errors="ignore").strip()
                cmd_buffer.clear()

                if full_cmd:
                    entry_id = await publish_command(session_id, full_cmd, {
                        "username": username,
                        "target": f"{target_host}:{target_port}",
                    })

                    verdict_data = await wait_verdict(session_id, entry_id, timeout=2.0)
                    verdict = verdict_data.get("verdict", "deny")

                    if verdict == "allow":
                        target_chan.sendall(char)
                    elif verdict == "deny":
                        reason = verdict_data.get("reason", "Blocked by policy")
                        admin_chan.sendall(
                            f"\r\n\033[91m[AI DEFENSE] BLOCKED: {reason}\033[0m\r\n".encode()
                        )
                        target_chan.sendall(b"\x03\x15")
                    else:
                        reason = verdict_data.get("reason", "Requires approval")
                        admin_chan.sendall(
                            f"\r\n\033[93m[ESCALATION] {reason}\033[0m\r\n".encode()
                        )
                        target_chan.sendall(b"\x03\x15")
                else:
                    target_chan.sendall(char)
            elif char == b"\x03":
                cmd_buffer.clear()
                target_chan.sendall(char)
            elif char == b"\x7f" or char == b"\x08":
                if cmd_buffer:
                    cmd_buffer.pop()
                target_chan.sendall(char)
            else:
                cmd_buffer.append(char)
                target_chan.sendall(char)

    except Exception as e:
        log.error("Session %s error: %s", session_id, e)
    finally:
        control_task.cancel()
        bridge_task.cancel()
        admin_chan.close()
        ssh.close()
        log.info("Session %s ended", session_id)


async def serve() -> None:
    settings = get_settings()
    host_key = paramiko.RSAKey.generate(2048)
    port = settings.bastion_port

    loop = asyncio.get_event_loop()

    import socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setblocking(False)
    server_sock.bind(("0.0.0.0", port))
    server_sock.listen(10)

    print(f"""
{CLR['bold']}{CLR['cyan']}
╔══════════════════════════════════════════════════════════╗
║         4SSH-Ultimate — Async AI Defense Bastion          ║
║                                                           ║
║  Redis Stream → Rule Engine → Verdict → Session Control   ║
╚══════════════════════════════════════════════════════════╝
{CLR['reset']}""")
    log.info("Bastion listening on port %d", port)

    while True:
        client, addr = await loop.sock_accept(server_sock)
        log.info("Connection from %s:%d", addr[0], addr[1])
        asyncio.create_task(_handle_client(client, host_key, addr))


async def _handle_client(client, host_key, addr):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        gateway = GatewayServer()

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: transport.start_server(server=gateway))

        channel = await loop.run_in_executor(None, lambda: transport.accept(30))
        if channel is None:
            log.warning("No channel from %s", addr)
            transport.close()
            return

        settings = get_settings()
        await handle_session(
            channel, gateway,
            target_host=os.environ.get("TARGET_HOST", "localhost"),
            target_port=int(os.environ.get("TARGET_PORT", "22")),
            target_user=os.environ.get("TARGET_USER", "root"),
            target_pass=os.environ.get("TARGET_PASS", ""),
        )
    except Exception as e:
        log.error("Client handler error: %s", e)


if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        log.info("Bastion stopped")
