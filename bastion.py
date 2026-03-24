"""
4SSH_CONTROL — Multi-Agent AI Defense SSH Bastion
Принцип «четырёх глаз» с тремя нейросетевыми агентами вместо ручного контроля.
"""

import argparse
import logging
import os
import select
import socket
import sys
import termios
import threading
import time
import tty

import paramiko

import re

from ai_defense.core.config import load_config
from ai_defense.core.engine import AIEngine, fetch_network_config
from ai_defense.core.models import AgentDecision, FinalVerdict, Verdict

INTERACTIVE_PROGRAMS = re.compile(
    r"^(?:sudo\s+)?(?:vi|vim|nvim|nano|pico|emacs|mcedit|joe|jed"
    r"|less|more|most|view"
    r"|top|htop|btop|atop|iotop|nmon|glances"
    r"|mysql|psql|mongo|mongosh|redis-cli|sqlite3"
    r"|python3?|ipython|bpython|node|irb|lua|ghci|R"
    r"|ssh|telnet|ftp|sftp"
    r"|screen|tmux|byobu"
    r"|man|info"
    r"|mutt|neomutt|alpine"
    r"|mc|ranger|nnn|vifm"
    r"|docker\s+(?:exec\s+-it|run\s+-it|attach)"
    r"|kubectl\s+exec\s+-it"
    r"|crontab\s+-e"
    r"|journalctl"
    r")\b",
    re.IGNORECASE,
)

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
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(self, channel, term, width, height, px_w, px_h, modes) -> bool:
        return True


def _bridge_with_callback(target_chan: paramiko.Channel, callback) -> None:
    """Forward target stdout through a callback for processing."""
    try:
        while True:
            data = target_chan.recv(4096)
            if not data:
                break
            callback(data)
    except EOFError:
        pass
    except Exception as exc:
        log.warning("Target bridge error: %s", exc)


_SHELL_PROMPT_RE = re.compile(
    r"(?:"
    r"@.*[:\~].*[\$#]\s*$"         # user@host:~$  or  user@host:~/dir#
    r"|\]\s*[\$#]\s*$"             # [user@host ~]$
    r"|^[\w./~-]*\s*[\$#%]\s*$"    # path$ or path# or path% (but NOT > alone)
    r")",
)
_REPL_PROMPT_RE = re.compile(
    r"(?:"
    r">>>\s*$"                     # Python REPL
    r"|\.\.\.\s*$"                 # Python continuation
    r"|\w+>\s*$"                   # mysql>, redis>, mongo>, psql>, irb>
    r"|In\s*\[\d+\]:\s*$"         # IPython
    r")",
)


def _detect_shell_return(text: str) -> bool:
    """Heuristic: detect if target output looks like we're back at a shell prompt."""
    stripped = text.strip()
    if not stripped:
        return False
    last_line = stripped.splitlines()[-1].strip()
    if _REPL_PROMPT_RE.search(last_line):
        return False
    if _SHELL_PROMPT_RE.search(last_line):
        return True
    return False


def _detect_target_profile(engine: AIEngine, ssh_transport: paramiko.Transport,
                           initial_data: str = "") -> tuple[str, str]:
    """Auto-detect target device type from SSH banner and initial output.

    Returns (profile_name, vendor) or ("linux", "") if no network profile matches.
    """
    banner = ""
    try:
        banner_raw = ssh_transport.get_banner()
        if banner_raw:
            banner = banner_raw.decode("utf-8", errors="ignore")
    except Exception:
        pass

    combined = f"{banner}\n{initial_data}"

    for pname, profile in engine.cfg.target_profiles.items():
        if profile.type != "network":
            continue
        for pat in profile.detect_banner:
            if pat.lower() in combined.lower():
                log.info("Auto-detected profile '%s' via banner match: '%s'", pname, pat)
                return pname, profile.vendor

    for pname, profile in engine.cfg.target_profiles.items():
        if profile.type != "network":
            continue
        for pat in profile.detect_prompt:
            try:
                if re.search(pat, initial_data, re.MULTILINE):
                    log.info("Auto-detected profile '%s' via prompt match: '%s'", pname, pat)
                    return pname, profile.vendor
            except re.error:
                pass

    return "linux", ""


def handle_session(
    admin_chan: paramiko.Channel,
    gateway: GatewayServer,
    engine: AIEngine,
    target_host: str,
    target_port: int,
    target_user: str,
    target_pass: str,
    default_role: str = "ops",
) -> None:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    username = gateway.username or "unknown"
    role = _resolve_role(engine, username, default_role)
    session = None

    try:
        ssh.connect(target_host, target_port, target_user, target_pass)
        target_chan = ssh.invoke_shell()

        time.sleep(0.5)
        initial_data = ""
        if target_chan.recv_ready():
            raw = target_chan.recv(4096)
            initial_data = raw.decode("utf-8", errors="ignore")
            admin_chan.send(raw)
            sys.stdout.write(f"{CLR_TARGET}{initial_data}{CLR_RESET}")
            sys.stdout.flush()

        profile_name, vendor = _detect_target_profile(engine, ssh.get_transport(), initial_data)
        session = engine.create_session(username=username, role=role,
                                        target_profile=profile_name, target_vendor=vendor)

        is_network = engine.is_network_session(session)
        profile_display = f"{vendor}" if vendor else profile_name

        if is_network:
            profile_obj = engine.get_profile(profile_name)
            if profile_obj and profile_obj.context_command:
                print(f"{CLR_SYSTEM}[*] Загрузка конфигурации устройства ({profile_obj.context_command})...{CLR_RESET}")
                session.network_context = fetch_network_config(ssh, profile_obj)
                if session.network_context:
                    print(f"{CLR_SYSTEM}[*] Конфигурация загружена: {len(session.network_context)} байт{CLR_RESET}")
                else:
                    print(f"{CLR_WARN}[!] Не удалось загрузить конфигурацию устройства{CLR_RESET}")

        print(f"\n{CLR_BOLD}{CLR_CYAN}╔══════════════════════════════════════════════╗{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}║  Новая сессия: {session.session_id:<28} ║{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}║  Пользователь: {username:<28} ║{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}║  Роль: {role:<36} ║{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}║  Профиль: {profile_display:<32} ║{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}╚══════════════════════════════════════════════╝{CLR_RESET}\n")

        interactive_lock = threading.Lock()
        interactive_mode = False
        interactive_cmd = ""
        interactive_buffer: list[str] = []
        content_alert_sent = False

        def _on_target_data(data: bytes) -> None:
            nonlocal interactive_mode
            admin_chan.send(data)
            text = data.decode("utf-8", errors="ignore")
            sys.stdout.write(f"{CLR_TARGET}{text}{CLR_RESET}")
            sys.stdout.flush()
            if interactive_mode and _detect_shell_return(text):
                with interactive_lock:
                    interactive_mode = False
                _flush_interactive_buffer()
                print(f"\n{CLR_SYSTEM}[AI] Интерактивный режим завершён "
                      f"({interactive_cmd}). Контроль восстановлен.{CLR_RESET}")

        def _flush_interactive_buffer() -> None:
            nonlocal content_alert_sent
            if interactive_buffer:
                full_text = "".join(interactive_buffer)
                if full_text.strip():
                    session.add_command(
                        f"[содержимое внутри {interactive_cmd}]: {len(full_text)} символов",
                    )
                interactive_buffer.clear()
            content_alert_sent = False

        threading.Thread(
            target=_bridge_with_callback,
            args=(target_chan, _on_target_data),
            daemon=True,
        ).start()

        cmd_buffer: list[bytes] = []

        while True:
            readable, _, _ = select.select([admin_chan, sys.stdin], [], [], 0.5)

            if admin_chan in readable:
                char = admin_chan.recv(1)
                if not char:
                    break

                with interactive_lock:
                    in_interactive = interactive_mode

                if in_interactive:
                    target_chan.send(char)
                    decoded = char.decode("utf-8", errors="ignore")
                    interactive_buffer.append(decoded)
                    if not content_alert_sent and len(interactive_buffer) % 32 == 0:
                        buf_text = "".join(interactive_buffer)
                        threat = engine._rule_engine.scan_content(buf_text)
                        if threat:
                            content_alert_sent = True
                            print(
                                f"\n{CLR_ERROR}{CLR_BOLD}"
                                f"[CONTENT MONITOR] ОПАСНОЕ СОДЕРЖИМОЕ в {interactive_cmd}!"
                                f"{CLR_RESET}\n"
                                f"  {CLR_ERROR}{threat.reason}{CLR_RESET}\n"
                                f"  {CLR_TARGET}Severity: {threat.severity.value}{CLR_RESET}"
                            )
                            admin_chan.send(
                                f"\r\n{CLR_ERROR}[AI DEFENSE] ОБНАРУЖЕНО ОПАСНОЕ СОДЕРЖИМОЕ: "
                                f"{threat.reason}{CLR_RESET}\r\n".encode()
                            )
                            alert_verdict = FinalVerdict(
                                verdict=threat.verdict,
                                decisions=[threat],
                                reason=f"Опасное содержимое внутри {interactive_cmd}: {threat.reason}",
                            )
                            engine._audit.log_decision(session, f"[content:{interactive_cmd}]", alert_verdict)
                            engine._alerts.notify(session, f"[content:{interactive_cmd}]", alert_verdict)
                    continue

                if char == b"\x03":
                    cmd_buffer.clear()
                    target_chan.send(char)
                    continue

                if char in (b"\r", b"\n"):
                    from ai_defense.core.rule_engine import RuleEngine as _RE
                    full_cmd = _RE.sanitize(b"".join(cmd_buffer).decode("utf-8", errors="ignore"))

                    if full_cmd:
                        if INTERACTIVE_PROGRAMS.search(full_cmd):
                            verdict = engine.evaluate(full_cmd, session, ssh_client=ssh)

                            if verdict.verdict == Verdict.DENY:
                                admin_chan.send(
                                    f"\r\n{CLR_ERROR}[AI DEFENSE] КОМАНДА ЗАБЛОКИРОВАНА{CLR_RESET}\r\n".encode()
                                )
                                _send_deny_details(admin_chan, verdict)
                                target_chan.send(b"\x03")
                                admin_chan.send(b"\x15")
                            elif verdict.verdict == Verdict.ESCALATE:
                                result = _handle_escalation(admin_chan, full_cmd, verdict)
                                _log_escalation_result(engine, session, full_cmd, verdict, result)
                                if result:
                                    with interactive_lock:
                                        interactive_mode = True
                                    interactive_cmd = full_cmd
                                    target_chan.send(char)
                                    print(f"{CLR_SYSTEM}[AI] Интерактивный режим: "
                                          f"{CLR_BOLD}{full_cmd}{CLR_RESET}"
                                          f"{CLR_SYSTEM}. Passthrough до выхода.{CLR_RESET}")
                                else:
                                    admin_chan.send(
                                        f"\r\n{CLR_ERROR}[ЭСКАЛАЦИЯ] Отклонено{CLR_RESET}\r\n".encode()
                                    )
                                    target_chan.send(b"\x03")
                                    admin_chan.send(b"\x15")
                            else:
                                with interactive_lock:
                                    interactive_mode = True
                                interactive_cmd = full_cmd
                                target_chan.send(char)
                                print(f"{CLR_SYSTEM}[AI] Интерактивный режим: "
                                      f"{CLR_BOLD}{full_cmd}{CLR_RESET}"
                                      f"{CLR_SYSTEM}. Passthrough до выхода.{CLR_RESET}")
                        else:
                            verdict = engine.evaluate(full_cmd, session, ssh_client=ssh)

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
                                _log_escalation_result(engine, session, full_cmd, verdict, result)
                                if result:
                                    target_chan.send(char)
                                else:
                                    admin_chan.send(
                                        f"\r\n{CLR_ERROR}[ЭСКАЛАЦИЯ] Отклонено{CLR_RESET}\r\n".encode()
                                    )
                                    target_chan.send(b"\x03")
                                    admin_chan.send(b"\x15")
                    else:
                        target_chan.send(char)

                    cmd_buffer.clear()
                else:
                    if char == b"\x7f" or char == b"\x08":
                        if cmd_buffer:
                            cmd_buffer.pop()
                    elif char == b"\x1b":
                        pass
                    elif char[0:1] < b"\x20" and char not in (b"\t",):
                        pass
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
        if session is not None:
            engine.end_session(session)
            print(f"{CLR_SYSTEM}[*] Сессия {session.session_id} завершена{CLR_RESET}")
        admin_chan.close()
        ssh.close()


def _resolve_role(engine: AIEngine, username: str, default_role: str = "ops") -> str:
    users = engine.cfg.rbac.users
    if username in users:
        return users[username].role
    return default_role if default_role else "ops"


def _send_deny_details(admin_chan: paramiko.Channel, verdict) -> None:
    for d in verdict.decisions:
        if d.reason:
            line = f"  {CLR_TARGET}• {d.agent_name}: {d.reason}{CLR_RESET}\r\n"
            admin_chan.send(line.encode())


def _log_escalation_result(engine: AIEngine, session, command: str, original_verdict, approved: bool) -> None:
    """Record admin's escalation decision in audit so dashboard reflects the final outcome."""
    final_verdict_val = Verdict.ALLOW if approved else Verdict.DENY
    admin_decision = AgentDecision(
        agent_name="admin_escalation",
        verdict=final_verdict_val,
        confidence=1.0,
        reason=f"Admin-2 {'разрешил' if approved else 'отклонил'} после эскалации",
    )
    all_decisions = list(original_verdict.decisions) + [admin_decision]
    final = FinalVerdict(
        verdict=final_verdict_val,
        decisions=all_decisions,
        reason=f"Эскалация → Admin-2: {'РАЗРЕШЕНО' if approved else 'ОТКЛОНЕНО'}",
        escalated=True,
    )
    engine._audit.log_decision(session, command, final)


def _handle_escalation(admin_chan: paramiko.Channel, command: str, verdict) -> bool:
    """When AI is unsure — ask local Admin-2 for manual override."""
    admin_chan.send(f"\r\n{CLR_SYSTEM}[AI DEFENSE] Команда передана на эскалацию...{CLR_RESET}\r\n".encode())

    reasons = []
    for d in verdict.decisions:
        if d.reason:
            reasons.append(f"{d.agent_name}: {d.reason}")

    try:
        tw = os.get_terminal_size().columns
    except (AttributeError, ValueError, OSError):
        tw = 80
    BOX_W = min(max(tw, 40), 80)
    inner = BOX_W - 4

    print(f"\n{CLR_BOLD}{CLR_SYSTEM}╔{'═' * (BOX_W - 2)}╗{CLR_RESET}")
    print(f"{CLR_SYSTEM}║  {'AI не уверен. Требуется решение Admin-2.':<{inner}}║{CLR_RESET}")
    _print_box_line(f"Команда: {command}", inner, CLR_ADMIN1)
    for r in reasons:
        _print_box_line(r, inner, CLR_TARGET)
    print(f"{CLR_SYSTEM}╚{'═' * (BOX_W - 2)}╝{CLR_RESET}")

    sys.stdout.write(f"{CLR_SYSTEM}[ЭСКАЛАЦИЯ] Разрешить? [y/n]: {CLR_RESET}")
    sys.stdout.flush()

    ch = sys.stdin.read(1)

    approved = ch.lower() in ("y", "т", "t", "l")
    if approved:
        print(f"{CLR_SUCCESS} РАЗРЕШЕНО (Admin-2){CLR_RESET}")
    else:
        print(f"{CLR_ERROR} ОТКЛОНЕНО (Admin-2){CLR_RESET}")
    return approved


def _print_box_line(text: str, inner_width: int, color: str = "") -> None:
    """Print a line inside a box, wrapping long text across multiple lines."""
    c = color or CLR_SYSTEM
    while len(text) > inner_width:
        chunk = text[:inner_width]
        text = text[inner_width:]
        print(f"{CLR_SYSTEM}║  {c}{chunk}{CLR_RESET}{CLR_SYSTEM}║{CLR_RESET}")
    print(f"{CLR_SYSTEM}║  {c}{text:<{inner_width}}{CLR_RESET}{CLR_SYSTEM}║{CLR_RESET}")


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
                    default_role=args.role or "ops",
                )
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        engine.close()
        print(f"\n{CLR_SYSTEM}[*] Бастион остановлен.{CLR_RESET}")


if __name__ == "__main__":
    main()
