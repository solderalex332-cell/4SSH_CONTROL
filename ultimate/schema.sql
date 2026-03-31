-- 4SSH-Ultimate: PostgreSQL Deep Audit Schema
-- Supports: RBAC, audit logging, session tracking, server inventory, VT scans

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ═══════════════════════════════════════════════════════════════
-- RBAC
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE roles (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(64) UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    allowed_commands TEXT[] NOT NULL DEFAULT '{}',
    denied_commands  TEXT[] NOT NULL DEFAULT '{}',
    is_admin    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(128) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role_id     INT REFERENCES roles(id) ON DELETE SET NULL,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    last_login  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    label       VARCHAR(128) NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════
-- Server Inventory
-- ═══════════════════════════════════════════════════════════════

CREATE TYPE server_type AS ENUM ('linux', 'cisco_ios', 'junos', 'mikrotik', 'huawei_vrp', 'arista_eos', 'generic_network');

CREATE TABLE servers (
    id              SERIAL PRIMARY KEY,
    hostname        VARCHAR(256) NOT NULL,
    ip_address      INET NOT NULL,
    port            INT NOT NULL DEFAULT 22,
    server_type     server_type NOT NULL DEFAULT 'linux',
    vendor          VARCHAR(64) NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    ssh_username    VARCHAR(128) NOT NULL DEFAULT '',
    ssh_key_path    TEXT,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    health_status   VARCHAR(32) NOT NULL DEFAULT 'unknown',
    last_health_check TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(ip_address, port)
);

-- ═══════════════════════════════════════════════════════════════
-- Sessions
-- ═══════════════════════════════════════════════════════════════

CREATE TYPE session_status AS ENUM ('active', 'completed', 'killed', 'frozen', 'error');

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         INT REFERENCES users(id),
    server_id       INT REFERENCES servers(id),
    username        VARCHAR(128) NOT NULL,
    role            VARCHAR(64) NOT NULL DEFAULT '',
    server_profile  server_type NOT NULL DEFAULT 'linux',
    server_vendor   VARCHAR(64) NOT NULL DEFAULT '',
    client_ip       INET,
    status          session_status NOT NULL DEFAULT 'active',
    command_count   INT NOT NULL DEFAULT 0,
    threat_score    FLOAT NOT NULL DEFAULT 0.0,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    network_context TEXT
);

CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_sessions_started ON sessions(started_at DESC);

-- ═══════════════════════════════════════════════════════════════
-- Audit Log (commands)
-- ═══════════════════════════════════════════════════════════════

CREATE TYPE verdict_type AS ENUM ('allow', 'deny', 'escalate');
CREATE TYPE severity_type AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    session_id      UUID REFERENCES sessions(id) ON DELETE CASCADE,
    username        VARCHAR(128) NOT NULL,
    role            VARCHAR(64) NOT NULL DEFAULT '',
    command         TEXT NOT NULL,
    sanitized_cmd   TEXT NOT NULL DEFAULT '',
    verdict         verdict_type NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    severity        severity_type NOT NULL DEFAULT 'low',
    category        VARCHAR(32) NOT NULL DEFAULT 'unknown',
    is_escalated    BOOLEAN NOT NULL DEFAULT FALSE,
    admin_decision  VARCHAR(16),
    agent_decisions JSONB NOT NULL DEFAULT '[]',
    server_profile  server_type NOT NULL DEFAULT 'linux',
    server_vendor   VARCHAR(64) NOT NULL DEFAULT '',
    elapsed_ms      FLOAT NOT NULL DEFAULT 0.0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_session ON audit_log(session_id);
CREATE INDEX idx_audit_verdict ON audit_log(verdict);
CREATE INDEX idx_audit_severity ON audit_log(severity);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX idx_audit_username ON audit_log(username);

-- ═══════════════════════════════════════════════════════════════
-- VirusTotal Scans
-- ═══════════════════════════════════════════════════════════════

CREATE TYPE scan_status AS ENUM ('pending', 'clean', 'malicious', 'suspicious', 'error');

CREATE TABLE vt_scans (
    id              BIGSERIAL PRIMARY KEY,
    session_id      UUID REFERENCES sessions(id) ON DELETE CASCADE,
    file_name       TEXT NOT NULL,
    file_path       TEXT NOT NULL DEFAULT '',
    sha256          VARCHAR(64) NOT NULL,
    file_size       BIGINT NOT NULL DEFAULT 0,
    scan_status     scan_status NOT NULL DEFAULT 'pending',
    detection_count INT NOT NULL DEFAULT 0,
    total_engines   INT NOT NULL DEFAULT 0,
    vt_link         TEXT,
    raw_result      JSONB,
    triggered_action VARCHAR(32),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vt_sha256 ON vt_scans(sha256);
CREATE INDEX idx_vt_status ON vt_scans(scan_status);

-- ═══════════════════════════════════════════════════════════════
-- Security Alerts
-- ═══════════════════════════════════════════════════════════════

CREATE TYPE alert_type AS ENUM ('command_deny', 'command_escalate', 'file_malicious', 'session_kill', 'rate_limit', 'intrusion');

CREATE TABLE alerts (
    id              BIGSERIAL PRIMARY KEY,
    session_id      UUID REFERENCES sessions(id) ON DELETE CASCADE,
    alert_type      alert_type NOT NULL,
    severity        severity_type NOT NULL DEFAULT 'high',
    title           TEXT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '',
    acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by INT REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_unack ON alerts(acknowledged) WHERE NOT acknowledged;
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);

-- ═══════════════════════════════════════════════════════════════
-- Time-based Policies
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE time_policies (
    id              SERIAL PRIMARY KEY,
    role_id         INT REFERENCES roles(id) ON DELETE CASCADE,
    high_risk_start TIME NOT NULL DEFAULT '22:00',
    high_risk_end   TIME NOT NULL DEFAULT '06:00',
    timezone        VARCHAR(64) NOT NULL DEFAULT 'Europe/Moscow',
    action          VARCHAR(16) NOT NULL DEFAULT 'escalate'
);

-- ═══════════════════════════════════════════════════════════════
-- Seed data
-- ═══════════════════════════════════════════════════════════════

INSERT INTO roles (name, description, allowed_commands, denied_commands, is_admin) VALUES
    ('admin',   'Full access administrator',        '{"*"}',                    '{}', TRUE),
    ('ops',     'Operations engineer',              '{"*"}',                    '{"rm -rf /","dd if=/dev/zero","mkfs","shutdown","reboot","init 0"}', FALSE),
    ('dev',     'Developer with limited access',    '{"ls","cat","grep","find","ps","top","df","du","head","tail","less","more","wc","sort","uniq","awk","sed","curl","wget","git","docker ps","docker logs","kubectl get","kubectl describe","kubectl logs"}', '{"rm","kill","systemctl","chmod","chown","mount","umount"}', FALSE),
    ('auditor', 'Read-only auditor',                '{"ls","cat","grep","find","ps","top","df","du","head","tail","less","more","wc","sort","uniq"}', '{"rm","kill","systemctl","chmod","chown","mount","umount","mv","cp","mkdir","rmdir","touch","wget","curl"}', FALSE);

INSERT INTO users (username, password_hash, role_id) VALUES
    ('admin', crypt('admin', gen_salt('bf')), 1);
