-- PostgreSQL: fleet state and control-plane records.
-- Carried over close to verbatim from the blueprint's schema.

CREATE SCHEMA IF NOT EXISTS enterprise_control;

CREATE TABLE enterprise_control.agents (
    agent_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(128) NOT NULL,
    mac_address MACADDR,
    ip_internal INET,
    client_certificate_serial VARCHAR(128),
    status VARCHAR(32) DEFAULT 'OFFLINE',
    last_heartbeat TIMESTAMPTZ,
    enrolled_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE enterprise_control.enrollment_tokens (
    token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_secret VARCHAR(128) UNIQUE NOT NULL,
    created_by VARCHAR(128) NOT NULL,
    max_uses INT DEFAULT 1,
    current_uses INT DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE
);

CREATE TABLE enterprise_control.command_queue (
    command_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(64) REFERENCES enterprise_control.agents(agent_id),
    action_type VARCHAR(64) NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(32) DEFAULT 'QUEUED',
    issued_by VARCHAR(128) NOT NULL,
    dispatched_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_payload JSONB
);

CREATE TABLE enterprise_control.audit_ledger (
    audit_id BIGSERIAL PRIMARY KEY,
    admin_identifier VARCHAR(128) NOT NULL,
    target_agent_id VARCHAR(64),
    action_dispatched VARCHAR(128) NOT NULL,
    session_log_reference VARCHAR(255),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_agents_status ON enterprise_control.agents(status);
CREATE INDEX idx_command_queue_agent ON enterprise_control.command_queue(agent_id, status);

-- ─────────────────────────────────────────────────────────────────────────
-- Dashboard login: username/password auth for the REST API + web UI.
-- A single bootstrap admin is auto-created on first run with a random
-- password printed once to the server log (see internal/auth).
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE enterprise_control.users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) DEFAULT 'ADMIN',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Sessions are also cached in memory for speed, but kept here so a login
-- survives a server restart instead of forcing everyone to sign in again.
CREATE TABLE enterprise_control.sessions (
    token VARCHAR(64) PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    role VARCHAR(32) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_expires ON enterprise_control.sessions(expires_at);
