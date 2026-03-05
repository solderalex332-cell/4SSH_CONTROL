# 4SSH_CONTROL

This repository contains a Proof-of-Concept (PoC) for an SSH bastion server that enforces the "four-eyes principle" for administrative access. It acts as a Man-in-the-Middle (MITM) proxy, intercepting all commands from one administrator (Admin-1) and requiring real-time approval from a second administrator (Admin-2) before execution on the target server.

## Concept

The system involves four components:

1.  **Admin-1 (Operator):** The primary administrator who connects to the bastion and intends to run commands on the target server.
2.  **Bastion Host (Proxy):** An intermediate server running the Python script. It accepts the connection from Admin-1, establishes its own connection to the Target Host, and manages the command approval flow.
3.  **Admin-2 (Controller):** A second administrator who monitors the bastion's console. They see every command Admin-1 attempts to execute and must explicitly approve (`y`) or deny (`n`) it.
4.  **Target Host:** The end server (e.g., production server, router) being administered. It only receives commands that have been approved by Admin-2.

The workflow is as follows:
```
Admin-1 SSH Session --> [ Bastion Server ] --> Target Server
                           ^          |
                           |          |
      (Command & Output) --+          +-- (Approve/Deny Prompt)
                           |
                           |
                     Admin-2 Console
```

## Implementations

This repository includes two different implementations of the bastion server.

### `main.py` - Simple Controller

This is a straightforward implementation where Admin-2's role is strictly to approve or deny commands.

*   **Functionality:** Intercepts each command entered by Admin-1 (after they press Enter) and prompts Admin-2 for a `y/n` decision in the bastion's terminal.
*   **Admin-2 Interaction:** Can only approve or deny commands. Cannot type into the session.
*   **Output:** The terminal output is color-coded to distinguish between system messages, Admin-1's proposed commands, and output from the target server.

### `secmain.py` - Interactive Controller

This is an advanced version that allows for a more collaborative session.

*   **Functionality:** In addition to approving/denying Admin-1's commands, Admin-2 can also type directly into the target session from the bastion's console.
*   **Admin-2 Interaction:** Can approve/deny commands from Admin-1 *and* type their own commands. Admin-1 sees the input and output from Admin-2's actions in their own session.
*   **Technology:** Uses `select` to simultaneously monitor input from Admin-1's SSH channel and Admin-2's local terminal (`stdin`).

## Requirements

The only external dependency is the `paramiko` library.

```bash
pip install paramiko
```

## Usage

1.  **Start the Bastion Server (Admin-2)**

    On the bastion machine, run either script with the connection details for the target server. The script will listen for connections from Admin-1.

    ```bash
    # For the simple controller
    python main.py --host <TARGET_IP> --user <TARGET_USER> --password <TARGET_PASS>

    # For the interactive controller
    python secmain.py --host <TARGET_IP> --user <TARGET_USER> --password <TARGET_PASS>
    ```
    **Arguments:**
    *   `--host`: IP address of the target server.
    *   `--user`: Username for the target server.
    *   `--password`: Password for the target server.
    *   `--port` (optional): SSH port of the target server (default: 22).
    *   `--listen` (optional): Port for the bastion to listen on (default: 2222).


2.  **Connect to the Bastion (Admin-1)**

    Admin-1 connects to the bastion server using a standard SSH client. The username and password for this connection are ignored, as authentication is automatically successful.

    ```bash
    ssh anyuser@<BASTION_IP> -p 2222
    ```

3.  **Monitor and Control (Admin-2)**

    Admin-2 watches the terminal where the bastion script is running.

    *   When Admin-1 types a command and presses `Enter`, it will appear in Admin-2's terminal with a confirmation prompt.
    *   Admin-2 presses `y` to allow the command or `n` to block it.
    *   If using `secmain.py`, Admin-2 can also type directly into this terminal to interact with the target server.

### Example Workflow

1.  **Admin-2** starts the server:
    ```
    python main.py --host 192.168.1.100 --user root --password toor
    ```
    Output:
    ```
    [*] Бастион запущен на порту 2222
    [*] Целевой узел: root@192.168.1.100:22
    [ГОТОВ] Ожидание подключения первого администратора...
    ```
2.  **Admin-1** connects:
    ```
    ssh john@<BASTION_IP> -p 2222
    ```
3.  **Admin-1** types `ls -l` and presses `Enter`.

4.  **Admin-2's** console shows the approval prompt:
    ```
    [КОНТРОЛЬ] Запрос на команду: ls -l | Разрешить? [y/n]:
    ```
5.  **Admin-2** presses `y`.

6.  The command is executed on the target, and the output is displayed in both Admin-1's SSH session and Admin-2's console (in grey).