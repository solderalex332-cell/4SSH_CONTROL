import paramiko
import threading
import socket
import argparse
import sys
import tty
import termios
import select

# Цветовые коды ANSI
CLR_RESET = "\033[0m"
CLR_ADMIN1_INPUT = "\033[94m" # Синий (Ввод 1-го админа)
CLR_ADMIN2_INPUT = "\033[95m" # Пурпурный (Ваш ввод)
CLR_SYSTEM = "\033[93m"       # Желтый (Система)
CLR_SUCCESS = "\033[92m"      # Зеленый (Разрешено)
CLR_ERROR = "\033[91m"        # Красный (Запрещено)
CLR_TARGET_OUT = "\033[90m"   # Серый (Ответ сервера)

class GatewayServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password): return paramiko.AUTH_SUCCESSFUL
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED
    def check_channel_shell_request(self, channel): return True
    def check_channel_pty_request(self, channel, term, width, height, px_w, px_h, modes): return True

def bridge_target_to_both(target_chan, admin_chan):
    """Трансляция ответа сервера обоим администраторам"""
    try:
        while True:
            if target_chan.recv_ready():
                data = target_chan.recv(4096)
                if not data: break
                admin_chan.send(data)
                sys.stdout.write(f"{CLR_TARGET_OUT}{data.decode('utf-8', errors='ignore')}{CLR_RESET}")
                sys.stdout.flush()
    except: pass

def get_single_char():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def handle_session(admin_chan, args):
    ssh_target = paramiko.SSHClient()
    ssh_target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh_target.connect(args.host, args.port, args.user, args.password)
        target_chan = ssh_target.invoke_shell()
        
        # Поток для вывода от сервера
        threading.Thread(target=bridge_target_to_both, args=(target_chan, admin_chan), daemon=True).start()

        cmd_buffer_a1 = [] # Буфер для Первого админа
        
        print(f"{CLR_SUCCESS}[СИСТЕМА] Соединение установлено. Вы можете вводить команды напрямую.{CLR_RESET}")
        
        while True:
            # Используем select для мониторинга ввода от Первого админа и от Вас (stdin)
            r, _, _ = select.select([admin_chan, sys.stdin], [], [])

            if admin_chan in r:
                char = admin_chan.recv(1)
                if not char: break

                if char in [b'\r', b'\n']:
                    full_cmd = b"".join(cmd_buffer_a1).decode('utf-8', errors='ignore').strip()
                    if full_cmd:
                        # Временный выход из сырого режима для вывода вопроса
                        sys.stdout.write(f"\n{CLR_SYSTEM}[КОНТРОЛЬ] Команда от Админа-1: {CLR_ADMIN1_INPUT}{full_cmd}{CLR_SYSTEM} | Разрешить? [Т/н]: {CLR_RESET}")
                        sys.stdout.flush()
                        
                        choice = get_single_char().lower()
                        if choice in ['т', 't', 'y', 'l']:
                            sys.stdout.write(f"{CLR_SUCCESS} ТАК ТОЧНО!{CLR_RESET}\n")
                            target_chan.send(char)
                        else:
                            sys.stdout.write(f"{CLR_ERROR} НИКАК НЕТ!{CLR_RESET}\n")
                            admin_chan.send(b"\r\n" + f"{CLR_ERROR}[БЛОК] НИКАК НЕТ!{CLR_RESET}\r\n".encode())
                            target_chan.send(b"\x03") 
                            admin_chan.send(b"\x15")
                    else:
                        target_chan.send(char)
                    cmd_buffer_a1 = []
                else:
                    if char == b'\x7f':
                        if cmd_buffer_a1: cmd_buffer_a1.pop()
                    else:
                        cmd_buffer_a1.append(char)
                    target_chan.send(char)

            if sys.stdin in r:
                # Ваш прямой ввод на целевой сервер
                char_v2 = sys.stdin.read(1)
                if char_v2:
                    # Отправляем ваш ввод на сервер и дублируем Первому админу, чтобы он видел, что вы делаете
                    target_chan.send(char_v2)
                    admin_chan.send(char_v2.encode())

    except Exception as e:
        print(f"\n{CLR_ERROR}[!] Ошибка: {e}{CLR_RESET}")
    finally:
        admin_chan.close()
        ssh_target.close()

def main():
    parser = argparse.ArgumentParser(description="SSH Bastion: Dual Admin Control")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--listen", type=int, default=2222)
    args = parser.parse_args()

    host_key = paramiko.RSAKey.generate(2048)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', args.listen))
    server_sock.listen(5)
    
    print(f"{CLR_SYSTEM}[*] Бастион запущен на порту {args.listen}. Ожидаю Админа-1...{CLR_RESET}")
    
    # Чтобы ваш ввод считывался посимвольно сразу
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            client, _ = server_sock.accept()
            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            transport.start_server(server=GatewayServer())
            channel = transport.accept(20)
            if channel:
                handle_session(channel, args)
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        print(f"\n{CLR_SYSTEM}[*] Завершение работы.{CLR_RESET}")

if __name__ == "__main__":
    main()

