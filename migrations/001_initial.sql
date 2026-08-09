-- Ambient API — Initial Schema
-- Run via: psql $DATABASE_URL -f migrations/001_initial.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────
-- Advertisers
-- ─────────────────────────────────────────────
CREATE TABLE advertisers (
  advertiser_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name            TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- Advertiser users (portal auth)
-- ─────────────────────────────────────────────
CREATE TABLE advertiser_users (
  user_id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  advertiser_id   TEXT NOT NULL REFERENCES advertisers(advertiser_id),
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  role            TEXT NOT NULL DEFAULT 'advertiser',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_advertiser_users_email ON advertiser_users(email);

-- ─────────────────────────────────────────────
-- Publishers
-- ─────────────────────────────────────────────
CREATE TABLE publishers (
  publisher_id    TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name            TEXT NOT NULL,
  contact_email   TEXT NOT NULL,              -- stored here only; never in ad path
  api_key_hash    TEXT NOT NULL,              -- bcrypt hash of the full key
  api_key_prefix  TEXT NOT NULL,              -- first 8 chars for display
  status          TEXT NOT NULL DEFAULT 'active',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- Campaigns
-- Warden requirement: advertiser_category non-nullable
-- ─────────────────────────────────────────────
CREATE TABLE campaigns (
  campaign_id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  advertiser_id          TEXT NOT NULL REFERENCES advertisers(advertiser_id),
  name                   TEXT NOT NULL,
  advertiser_category    TEXT NOT NULL,       -- Warden: non-nullable; hard-reject blocked at API
  status                 TEXT NOT NULL DEFAULT 'draft',
  -- Creative
  headline               TEXT NOT NULL CHECK (char_length(headline) <= 60),
  body                   TEXT NOT NULL CHECK (char_length(body) <= 150),
  cta_text               TEXT NOT NULL CHECK (char_length(cta_text) <= 20),
  destination_url        TEXT NOT NULL,
  disclosure_label       TEXT NOT NULL CHECK (disclosure_label IN ('Ad', 'Sponsored')),
  disclosure_placement   TEXT NOT NULL CHECK (disclosure_placement IN ('prepend', 'surround')),
  -- Targeting (Signal Decision 2: pre-stemmed keywords stored here)
  targeting_keywords     TEXT[] NOT NULL DEFAULT '{}',
  targeting_keywords_stemmed TEXT[] NOT NULL DEFAULT '{}', -- pre-computed at creation
  targeting_surfaces     TEXT[] NOT NULL DEFAULT '{}',     -- empty = all surfaces
  -- Budget / pacing
  budget_total_cents     BIGINT NOT NULL,
  budget_daily_cents     BIGINT NOT NULL,
  cpm_floor_cents        BIGINT NOT NULL DEFAULT 0,        -- Signal Decision 3: ranking key
  -- Flight
  flight_start           TIMESTAMPTZ NOT NULL,
  flight_end             TIMESTAMPTZ NOT NULL,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT valid_flight CHECK (flight_end > flight_start)
);
CREATE INDEX idx_campaigns_status ON campaigns(status);
CREATE INDEX idx_campaigns_advertiser ON campaigns(advertiser_id);

-- ─────────────────────────────────────────────
-- API key audit log (key events, not impression events)
-- ─────────────────────────────────────────────
CREATE TABLE api_key_events (
  event_id        TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  publisher_id    TEXT NOT NULL REFERENCES publishers(publisher_id),
  event_type      TEXT NOT NULL,  -- 'issued' | 'revoked' | 'rotated'
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- Manual review queue (Warden conditional categories)
-- ─────────────────────────────────────────────
CREATE TABLE campaign_review_queue (
  review_id       TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  campaign_id     TEXT NOT NULL REFERENCES campaigns(campaign_id),
  reason          TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'approved' | 'rejected'
  reviewer_notes  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at     TIMESTAMPTZ
);

-- updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER campaigns_updated_at
  BEFORE UPDATE ON campaigns
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
