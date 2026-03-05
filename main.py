import paramiko
import threading
import socket
import argparse
import sys
import tty
import termios

# Цветовые коды ANSI для оформления консоли Admin-2
CLR_RESET = "\033[0m"
CLR_ADMIN1_INPUT = "\033[94m" # Светло-синий (Ввод первого админа)
CLR_SYSTEM = "\033[93m"       # Желтый (Системные уведомления бастиона)
CLR_SUCCESS = "\033[92m"      # Зеленый (Разрешено / Успех)
CLR_ERROR = "\033[91m"        # Красный (Заблокировано / Ошибка)
CLR_TARGET_OUT = "\033[90m"   # Серый (Ответ целевого сервера)

class GatewayServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password): return paramiko.AUTH_SUCCESSFUL
    def check_channel_request(self, kind, chanid): 
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_shell_request(self, channel): return True
    def check_channel_pty_request(self, channel, term, width, height, px_w, px_h, modes): return True

def bridge_target_to_both(target_chan, admin_chan):
    """Пересылка вывода от сервера: оригинал админу-1 и серый текст админу-2"""
    try:
        while True:
            data = target_chan.recv(4096)
            if not data: break
            admin_chan.send(data)
            
            output = data.decode('utf-8', errors='ignore')
            sys.stdout.write(f"{CLR_TARGET_OUT}{output}{CLR_RESET}")
            sys.stdout.flush()
    except: pass

def get_single_char():
    """Чтение одного символа (y/n) без нажатия Enter"""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
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
        
        threading.Thread(target=bridge_target_to_both, args=(target_chan, admin_chan), daemon=True).start()

        cmd_buffer = []
        while True:
            char = admin_chan.recv(1)
            if not char: break

            if char in [b'\r', b'\n']:
                full_cmd = b"".join(cmd_buffer).decode('utf-8', errors='ignore').strip()
                
                if full_cmd:
                    sys.stdout.write(f"\n{CLR_SYSTEM}[КОНТРОЛЬ] Запрос на команду: {CLR_ADMIN1_INPUT}{full_cmd}{CLR_SYSTEM} | Разрешить? [y/n]: {CLR_RESET}")
                    sys.stdout.flush()
                    
                    choice = get_single_char()
                    
                    if choice.lower() == 'y':
                        target_chan.send(char)
                        sys.stdout.write(f"{CLR_SUCCESS} РАЗРЕШЕНО{CLR_RESET}\n")
                    else:
                        admin_chan.send(b"\r" + b" " * (len(full_cmd) + 20) + b"\r")
                        admin_chan.send(f"\r\n{CLR_ERROR}[БЕЗОПАСНОСТЬ] КОМАНДА ЗАБЛОКИРОВАНА ВТОРЫМ АДМИНИСТРАТОРОМ{CLR_RESET}\r\n".encode())
                        target_chan.send(b"\x03") 
                        sys.stdout.write(f"{CLR_ERROR} ОТКЛОНЕНО{CLR_RESET}\n")
                else:
                    target_chan.send(char)
                cmd_buffer = []
            else:
                cmd_buffer.append(char)
                target_chan.send(char)

    except Exception as e:
        print(f"\n{CLR_ERROR}[!] Ошибка сессии: {e}{CLR_RESET}")
    finally:
        admin_chan.close()
        ssh_target.close()

def main():
    parser = argparse.ArgumentParser(
        description="SSH Бастион (PoC): Принцип 'Четырех глаз' с ручным подтверждением.",
        epilog="Пример: python bastion.py --host 192.168.1.10 --user root --password secret"
    )
    parser.add_argument("--host", required=True, help="IP целевого сервера")
    parser.add_argument("--port", type=int, default=22, help="Порт SSH цели (22)")
    parser.add_argument("--user", required=True, help="Логин на целевом сервере")
    parser.add_argument("--password", required=True, help="Пароль на целевом сервере")
    parser.add_argument("--listen", type=int, default=2222, help="Порт бастиона (2222)")
    args = parser.parse_args()

    host_key = paramiko.RSAKey.generate(2048)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', args.listen))
    server_sock.listen(5)
    
    print(f"{CLR_SYSTEM}[*] Бастион запущен на порту {args.listen}{CLR_RESET}")
    print(f"[*] Целевой узел: {args.user}@{args.host}:{args.port}")
    print(f"{CLR_SUCCESS}[ГОТОВ] Ожидание подключения первого администратора...{CLR_RESET}\n")
    
    try:
        while True:
            client, _ = server_sock.accept()
            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            transport.start_server(server=GatewayServer())
            channel = transport.accept(20)
            if channel:
                handle_session(channel, args)
    except KeyboardInterrupt:
        print(f"\n{CLR_SYSTEM}[*] Работа бастиона завершена.{CLR_RESET}")

if __name__ == "__main__":
    main()

