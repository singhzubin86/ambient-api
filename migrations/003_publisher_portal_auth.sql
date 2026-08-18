-- Migration 003: Publisher self-service portal auth
-- Spec: AMBIENT_PROTOTYPE_SPECS.md R3 SPEC-1, SPEC-2, SPEC-3
-- Adds: portal_users, email_verification_tokens, and extends publishers table
-- for self-service onboarding (app_name, app_url, app_category, mau_range,
-- integration_type, cpm_usd).

-- ─────────────────────────────────────────────
-- Portal users (publisher + advertiser self-service)
-- Distinct from advertiser_users which is admin-provisioned.
-- ─────────────────────────────────────────────
CREATE TABLE portal_users (
  user_id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  email            TEXT NOT NULL UNIQUE,
  full_name        TEXT NOT NULL,
  company_name     TEXT NOT NULL,
  password_hash    TEXT NOT NULL,
  role             TEXT NOT NULL CHECK (role IN ('publisher', 'advertiser', 'both')),
  verified         BOOLEAN NOT NULL DEFAULT FALSE,
  status           TEXT NOT NULL DEFAULT 'pending_verification'
                     CHECK (status IN ('pending_verification', 'active', 'suspended')),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_portal_users_email ON portal_users(email);

-- ─────────────────────────────────────────────
-- Email verification tokens
-- Token stored as HMAC-SHA256 hash, never plaintext.
-- ─────────────────────────────────────────────
CREATE TABLE email_verification_tokens (
  token_id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id          TEXT NOT NULL REFERENCES portal_users(user_id) ON DELETE CASCADE,
  token_hash       TEXT NOT NULL UNIQUE,  -- HMAC-SHA256(server_secret, raw_token)
  expires_at       TIMESTAMPTZ NOT NULL,
  used_at          TIMESTAMPTZ,           -- NULL = unused
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_email_tokens_user ON email_verification_tokens(user_id);
CREATE INDEX idx_email_tokens_hash ON email_verification_tokens(token_hash);

-- ─────────────────────────────────────────────
-- Extend publishers table for self-service onboarding
-- (SPEC-3: app_name, app_url, app_category, mau_range, integration_type, cpm_usd)
-- portal_user_id links publisher record to portal auth identity.
-- ─────────────────────────────────────────────
ALTER TABLE publishers
  ADD COLUMN IF NOT EXISTS portal_user_id  TEXT REFERENCES portal_users(user_id),
  ADD COLUMN IF NOT EXISTS app_name        TEXT,
  ADD COLUMN IF NOT EXISTS app_url         TEXT,
  ADD COLUMN IF NOT EXISTS app_category    TEXT
    CHECK (app_category IS NULL OR app_category IN
      ('custom_gpt','standalone_chatbot','voice_ai','rag_app','other')),
  ADD COLUMN IF NOT EXISTS mau_range       TEXT
    CHECK (mau_range IS NULL OR mau_range IN ('lt1k','1k_10k','10k_100k','100k_plus')),
  ADD COLUMN IF NOT EXISTS integration_type TEXT
    CHECK (integration_type IS NULL OR integration_type IN ('standalone_web_chatbot','other')),
  ADD COLUMN IF NOT EXISTS cpm_usd         NUMERIC(10,4) NOT NULL DEFAULT 5.00;

CREATE UNIQUE INDEX idx_publishers_portal_user ON publishers(portal_user_id)
  WHERE portal_user_id IS NOT NULL;
CREATE UNIQUE INDEX idx_publishers_app_url ON publishers(app_url, portal_user_id)
  WHERE app_url IS NOT NULL;

-- ─────────────────────────────────────────────
-- JWT denylist (SPEC-1: logout invalidation)
-- jti stored, TTL enforced by periodic cleanup or Redis in middleware.
-- Using Redis for runtime denylist (see auth middleware); this table is
-- a durable fallback and audit log.
-- ─────────────────────────────────────────────
CREATE TABLE jwt_denylist (
  jti              TEXT PRIMARY KEY,
  expires_at       TIMESTAMPTZ NOT NULL,
  invalidated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_jwt_denylist_expires ON jwt_denylist(expires_at);

-- Resend rate limiting for email verification (SPEC-2: max 3/hr per email)
CREATE TABLE email_resend_log (
  log_id     TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  email      TEXT NOT NULL,
  sent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_resend_log_email_time ON email_resend_log(email, sent_at);

-- updated_at trigger for portal_users
CREATE TRIGGER portal_users_updated_at
  BEFORE UPDATE ON portal_users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
