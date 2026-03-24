"""
4SSH_CONTROL — Multi-Agent AI Defense SSH Bastion
Принцип «четырёх глаз» с тремя нейросетевыми агентами вместо ручного контроля.
"""

import argparse
import logging
import select
import socket
import sys
import termios
import threading
import tty

import paramiko

from ai_defense.core.config import load_config
from ai_defense.core.engine import AIEngine
from ai_defense.core.models import Verdict

CLR_RESET = "\033[0m"
CLR_ADMIN1 = "\033[94m"
CLR_ADMIN2 = "\033[95m"
CLR_SYSTEM = "\033[93m"
CLR_SUCCESS = "\033[92m"
CLR_ERROR = "\033[91m"
CLR_TARGET = "\033[90m"
CLR_BOLD = "\033[1m"
CLR_CYAN = "\033[96m"

logging.basicConfig(
    level=logging.INFO,
    format=f"{CLR_TARGET}%(asctime)s [%(name)s] %(message)s{CLR_RESET}",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bastion")


class GatewayServer(paramiko.ServerInterface):
    """Paramiko SSH server that accepts any auth (PoC)."""

    def __init__(self) -> None:
        self.username: str = ""

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(self, channel, term, width, height, px_w, px_h, modes) -> bool:
        return True


def bridge_target_output(target_chan: paramiko.Channel, admin_chan: paramiko.Channel) -> None:
    """Forward target stdout → Admin-1 + local console mirror."""
    try:
        while True:
            data = target_chan.recv(4096)
            if not data:
                break
            admin_chan.send(data)
            text = data.decode("utf-8", errors="ignore")
            sys.stdout.write(f"{CLR_TARGET}{text}{CLR_RESET}")
            sys.stdout.flush()
    except Exception:
        pass


def handle_session(
    admin_chan: paramiko.Channel,
    gateway: GatewayServer,
    engine: AIEngine,
    target_host: str,
    target_port: int,
    target_user: str,
    target_pass: str,
) -> None:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    username = gateway.username or "unknown"
    role = _resolve_role(engine, username)
    session = engine.create_session(username=username, role=role)

    print(f"\n{CLR_BOLD}{CLR_CYAN}╔══════════════════════════════════════════════╗{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}║  Новая сессия: {session.session_id:<28} ║{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}║  Пользователь: {username:<28} ║{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}║  Роль: {role:<36} ║{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}╚══════════════════════════════════════════════╝{CLR_RESET}\n")

    try:
        ssh.connect(target_host, target_port, target_user, target_pass)
        target_chan = ssh.invoke_shell()

        threading.Thread(
            target=bridge_target_output,
            args=(target_chan, admin_chan),
            daemon=True,
        ).start()

        cmd_buffer: list[bytes] = []

        while True:
            readable, _, _ = select.select([admin_chan, sys.stdin], [], [], 0.5)

            if admin_chan in readable:
                char = admin_chan.recv(1)
                if not char:
                    break

                if char in (b"\r", b"\n"):
                    full_cmd = b"".join(cmd_buffer).decode("utf-8", errors="ignore").strip()

                    if full_cmd:
                        verdict = engine.evaluate(full_cmd, session)

                        if verdict.verdict == Verdict.ALLOW:
                            target_chan.send(char)
                        elif verdict.verdict == Verdict.DENY:
                            admin_chan.send(
                                f"\r\n{CLR_ERROR}[AI DEFENSE] КОМАНДА ЗАБЛОКИРОВАНА{CLR_RESET}\r\n".encode()
                            )
                            _send_deny_details(admin_chan, verdict)
                            target_chan.send(b"\x03")
                            admin_chan.send(b"\x15")
                        else:
                            result = _handle_escalation(admin_chan, full_cmd, verdict)
                            if result:
                                target_chan.send(char)
                            else:
                                admin_chan.send(
                                    f"\r\n{CLR_ERROR}[ЭСКАЛАЦИЯ] Отклонено администратором{CLR_RESET}\r\n".encode()
                                )
                                target_chan.send(b"\x03")
                                admin_chan.send(b"\x15")
                    else:
                        target_chan.send(char)

                    cmd_buffer = []
                else:
                    if char == b"\x7f":
                        if cmd_buffer:
                            cmd_buffer.pop()
                    else:
                        cmd_buffer.append(char)
                    target_chan.send(char)

            if sys.stdin in readable:
                local_char = sys.stdin.read(1)
                if local_char:
                    target_chan.send(local_char)
                    admin_chan.send(local_char.encode())

    except Exception as exc:
        print(f"\n{CLR_ERROR}[!] Ошибка сессии: {exc}{CLR_RESET}")
    finally:
        engine.end_session(session)
        admin_chan.close()
        ssh.close()
        print(f"{CLR_SYSTEM}[*] Сессия {session.session_id} завершена{CLR_RESET}")


def _resolve_role(engine: AIEngine, username: str) -> str:
    users = engine.cfg.rbac.users
    if username in users:
        return users[username].role
    return "ops"


def _send_deny_details(admin_chan: paramiko.Channel, verdict) -> None:
    for d in verdict.decisions:
        if d.reason:
            line = f"  {CLR_TARGET}• {d.agent_name}: {d.reason}{CLR_RESET}\r\n"
            admin_chan.send(line.encode())


def _handle_escalation(admin_chan: paramiko.Channel, command: str, verdict) -> bool:
    """When AI is unsure — ask local Admin-2 for manual override."""
    admin_chan.send(f"\r\n{CLR_SYSTEM}[AI DEFENSE] Команда передана на эскалацию...{CLR_RESET}\r\n".encode())

    reasons = []
    for d in verdict.decisions:
        if d.reason:
            reasons.append(f"  {d.agent_name}: {d.reason}")

    print(f"\n{CLR_BOLD}{CLR_SYSTEM}╔═══ ЭСКАЛАЦИЯ ═══════════════════════════════╗{CLR_RESET}")
    print(f"{CLR_SYSTEM}║ AI не уверен. Требуется решение Admin-2.    ║{CLR_RESET}")
    print(f"{CLR_SYSTEM}║ Команда: {CLR_ADMIN1}{command:<35}{CLR_SYSTEM}║{CLR_RESET}")
    for r in reasons:
        print(f"{CLR_SYSTEM}║ {CLR_TARGET}{r:<44}{CLR_SYSTEM}║{CLR_RESET}")
    print(f"{CLR_SYSTEM}╚═════════════════════════════════════════════╝{CLR_RESET}")

    sys.stdout.write(f"{CLR_SYSTEM}[ЭСКАЛАЦИЯ] Разрешить? [y/n]: {CLR_RESET}")
    sys.stdout.flush()

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

    approved = ch.lower() in ("y", "т", "t", "l")
    if approved:
        print(f"{CLR_SUCCESS} РАЗРЕШЕНО (Admin-2){CLR_RESET}")
    else:
        print(f"{CLR_ERROR} ОТКЛОНЕНО (Admin-2){CLR_RESET}")
    return approved


def print_banner() -> None:
    print(f"""{CLR_BOLD}{CLR_CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║          4SSH_CONTROL — Multi-Agent AI Defense           ║
    ║                                                          ║
    ║  Layer 0: Rule Engine        (мгновенный фильтр)         ║
    ║  Agent 1: Command Classifier (классификация команд)      ║
    ║  Agent 2: Context Analyzer   (анализ контекста сессии)   ║
    ║  Agent 3: Policy Enforcer    (RBAC + политики)           ║
    ║  Consensus: Weighted Voting  (агрегация решений)         ║
    ╚══════════════════════════════════════════════════════════╝
{CLR_RESET}""")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="4SSH_CONTROL: Multi-Agent AI Defense SSH Bastion",
    )
    parser.add_argument("--host", help="IP целевого сервера")
    parser.add_argument("--user", help="Логин на целевом сервере")
    parser.add_argument("--password", help="Пароль на целевом сервере")
    parser.add_argument("--port", type=int, default=22, help="Порт SSH цели")
    parser.add_argument("--listen", type=int, default=2222, help="Порт бастиона")
    parser.add_argument("--config", default="config.yaml", help="Путь к config.yaml")
    parser.add_argument("--role", default="", help="Роль по умолчанию для подключающихся")
    args = parser.parse_args()

    cfg = load_config(args.config)

    if args.host:
        cfg.bastion.target_host = args.host
    if args.user:
        cfg.bastion.target_user = args.user
    if args.password:
        cfg.bastion.target_password = args.password
    if args.port != 22:
        cfg.bastion.target_port = args.port
    if args.listen != 2222:
        cfg.bastion.listen_port = args.listen

    if not cfg.bastion.target_host or not cfg.bastion.target_user:
        parser.error("--host и --user обязательны (или задайте в config.yaml)")

    engine = AIEngine(cfg)

    print_banner()

    active_agents = [n for n, t in cfg.agents.items() if t.enabled]
    print(f"{CLR_SYSTEM}[*] Активные агенты: {', '.join(active_agents)}{CLR_RESET}")
    print(f"{CLR_SYSTEM}[*] LLM: {cfg.llm.provider}/{cfg.llm.model}{CLR_RESET}")
    print(f"{CLR_SYSTEM}[*] Консенсус: {cfg.consensus.strategy} (deny threshold={cfg.consensus.deny_threshold}){CLR_RESET}")
    print(f"{CLR_SYSTEM}[*] Правила: {len(cfg.rules.whitelist)} whitelist, {len(cfg.rules.blacklist)} blacklist{CLR_RESET}")
    print(f"{CLR_SYSTEM}[*] Целевой узел: {cfg.bastion.target_user}@{cfg.bastion.target_host}:{cfg.bastion.target_port}{CLR_RESET}")
    print(f"\n{CLR_SUCCESS}[READY] Бастион на порту {cfg.bastion.listen_port}. Ожидание подключений...{CLR_RESET}\n")

    host_key = paramiko.RSAKey.generate(2048)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", cfg.bastion.listen_port))
    server_sock.listen(5)

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            client, addr = server_sock.accept()
            print(f"\n{CLR_SYSTEM}[+] Подключение от {addr[0]}:{addr[1]}{CLR_RESET}")

            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            gateway = GatewayServer()
            transport.start_server(server=gateway)
            channel = transport.accept(20)
            if channel:
                handle_session(
                    channel,
                    gateway,
                    engine,
                    cfg.bastion.target_host,
                    cfg.bastion.target_port,
                    cfg.bastion.target_user,
                    cfg.bastion.target_password,
                )
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        engine.close()
        print(f"\n{CLR_SYSTEM}[*] Бастион остановлен.{CLR_RESET}")


if __name__ == "__main__":
    main()
