# 4SSH-Ultimate — Enterprise AI-SSH Bastion

Production-grade SSH gateway with AI-driven security engine, real-time audit monitoring, and interactive Vue 3 dashboard.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌────────────────┐
│  SSH Client   │────▶│  Bastion (Async  │────▶│  Target Server │
│  (port 2222)  │     │   Paramiko)      │     │  (port 22)     │
└──────────────┘     └───────┬──────────┘     └────────────────┘
                             │ keystroke → Redis Stream
                    ┌────────▼────────────┐
                    │  FastAPI Control     │
                    │  Plane (port 8000)   │
                    │  • Rule Engine L0/L1 │
                    │  • VirusTotal API    │
                    │  • WebSocket Hub     │
                    └───┬──────────┬──────┘
                        │          │
                ┌───────▼──┐  ┌───▼────────┐
                │  Redis    │  │  PostgreSQL │
                │  (Pub/Sub │  │  (Audit DB) │
                │   Streams)│  │             │
                └──────────┘  └─────────────┘
                        │
                ┌───────▼──────────────┐
                │  Vue 3 Dashboard     │
                │  • Xterm.js terminal │
                │  • Anime.js effects  │
                │  • Pinia + WebSocket │
                └──────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Transport | Python 3.12, Async Paramiko |
| Control Plane | FastAPI, Redis Streams/Pub-Sub |
| Database | PostgreSQL 16 |
| Security | Regex Rule Engine, VirusTotal API |
| Frontend | Vue 3, Vite, Tailwind CSS v4, Pinia, Xterm.js, Anime.js |
| Deployment | Docker Compose |

## Quick Start

```bash
cd ultimate
cp .env.example .env
# Edit .env with your target server and optional VT API key

docker compose up --build
```

### Access Points

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:5173 |
| API Docs | http://localhost:8000/docs |
| SSH Bastion | `ssh -p 2222 user@localhost` |

Default credentials: `admin` / `admin`

## Components

### SSH Interceptor (`bastion_async.py`)
- Async Paramiko SSH proxy
- Keystroke buffering → Redis Stream
- Session control via Redis Pub/Sub (KILL/FREEZE/WARNING)
- Strict mode: blocks all if Redis/API unreachable

### Control Plane (`api_main.py`)
- FastAPI with async SQLAlchemy + asyncpg
- Redis Stream consumer for command validation
- Layer 0/1 Rule Engine (blacklist, whitelist, escalation, chains, obfuscation detection)
- VirusTotal integration for file hash reputation
- WebSocket broadcasting to dashboard
- JWT authentication

### Dashboard (Vue 3)
- **Login**: Digital Rain animation (Anime.js canvas)
- **Dashboard**: Real-time stats, live command stream, security radar, VT scan panel
- **Sessions**: Card grid with KILL/FREEZE/WARN controls
- **Session Detail**: Xterm.js terminal mirror, command history
- **Logs**: Filterable audit log table
- **Servers**: Server inventory with health status
- **Alerts**: Security alerts with acknowledge workflow

## Database Schema

See `schema.sql` — tables:
- `roles`, `users`, `api_tokens` — RBAC
- `servers` — inventory with device type enum
- `sessions` — with threat scoring
- `audit_log` — every command with agent decisions (JSONB)
- `vt_scans` — VirusTotal file reputation results
- `alerts` — security alerts with acknowledge workflow
- `time_policies` — high-risk hours enforcement
