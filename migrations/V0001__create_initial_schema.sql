-- Initial schema for crazytrip-user-service
-- Includes auth, session, audit, and business team support

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enums (defensive creation for older Postgres versions)
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('User', 'Admin', 'Moderator');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE business_verification_status AS ENUM ('pending', 'under_review', 'approved', 'rejected', 'suspended');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE business_role AS ENUM ('owner', 'admin', 'member');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE audit_action AS ENUM (
        'business_created',
        'business_updated',
        'business_verified',
        'business_rejected',
        'member_invited',
        'member_joined',
        'member_removed',
        'role_changed',
        'ownership_transferred',
        'promotion_created',
        'promotion_updated',
        'promotion_deleted'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Core users table
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            user_role NOT NULL DEFAULT 'User',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ,
    login_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- Session management
CREATE TABLE IF NOT EXISTS sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL,
    refresh_token_hash  TEXT,
    ip_address          INET NOT NULL DEFAULT '0.0.0.0',
    user_agent          TEXT,
    expires_at          TIMESTAMPTZ NOT NULL,
    refresh_expires_at  TIMESTAMPTZ,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_sessions_token_hash UNIQUE (token_hash),
    CONSTRAINT uq_sessions_refresh_hash UNIQUE (refresh_token_hash)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Revoked token replay protection
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);

-- Error logging
CREATE TABLE IF NOT EXISTS error_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    message     TEXT NOT NULL,
    details     JSONB,
    request_id  TEXT,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_error_logs_created_at ON error_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_error_logs_category ON error_logs(category);
CREATE INDEX IF NOT EXISTS idx_error_logs_severity ON error_logs(severity);

-- Telemetry aggregates
CREATE TABLE IF NOT EXISTS telemetry_metrics_aggregate (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name TEXT NOT NULL,
    labels      JSONB,
    value       DOUBLE PRECISION NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_metrics_metric_name ON telemetry_metrics_aggregate(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_created_at ON telemetry_metrics_aggregate(created_at);

-- Business accounts
CREATE TABLE IF NOT EXISTS business_accounts (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT NOT NULL,
    category              TEXT NOT NULL,
    address               TEXT NOT NULL,
    description           TEXT,
    phone                 TEXT,
    website               TEXT,
    verification_status   business_verification_status NOT NULL DEFAULT 'pending',
    tax_id                TEXT,
    document_urls         TEXT[] NOT NULL DEFAULT '{}',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at           TIMESTAMPTZ,
    rejection_reason      TEXT
);

CREATE INDEX IF NOT EXISTS idx_business_accounts_status ON business_accounts(verification_status);
CREATE INDEX IF NOT EXISTS idx_business_accounts_created_at ON business_accounts(created_at);

-- Business team members
CREATE TABLE IF NOT EXISTS business_members (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_id  UUID NOT NULL REFERENCES business_accounts(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email        TEXT NOT NULL,
    username     TEXT NOT NULL,
    role         business_role NOT NULL DEFAULT 'member',
    invited_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    joined_at    TIMESTAMPTZ,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    invited_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT uq_business_member UNIQUE (business_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_business_members_business ON business_members(business_id);
CREATE INDEX IF NOT EXISTS idx_business_members_user ON business_members(user_id);
CREATE INDEX IF NOT EXISTS idx_business_members_role ON business_members(role);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_id     UUID NOT NULL REFERENCES business_accounts(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username        TEXT NOT NULL,
    action          audit_action NOT NULL,
    metadata        JSONB,
    target_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    target_username TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address      TEXT,
    user_agent      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_business ON audit_logs(business_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Schema migrations table (for migrate binary idempotency)
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    description TEXT,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
