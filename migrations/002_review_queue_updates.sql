-- Migration 002: Campaign status state machine + review fields + event_log table
-- Ledger requirements: pending_review state, rejection_reason, self_certified_compliance

ALTER TABLE campaigns
  ADD COLUMN IF NOT EXISTS rejection_reason TEXT,
  ADD COLUMN IF NOT EXISTS advertiser_self_certified_compliance BOOLEAN NOT NULL DEFAULT FALSE;

-- Extend status check to include all valid states
ALTER TABLE campaigns DROP CONSTRAINT IF EXISTS campaigns_status_check;
ALTER TABLE campaigns ADD CONSTRAINT campaigns_status_check
  CHECK (status IN ('draft', 'pending_review', 'active', 'paused', 'ended', 'rejected'));

-- event_log: denormalized table for reporting queries
-- Populated by the log-store flush worker from NDJSON files.
-- This is the authoritative record for billing (not Redis counters).
-- Deduplicate impressions on request_id at query time.
CREATE TABLE IF NOT EXISTS event_log (
  id                    BIGSERIAL PRIMARY KEY,
  event_type            TEXT NOT NULL,             -- 'impression' | 'click' | 'anomaly_flag'
  timestamp_utc_ms      BIGINT NOT NULL,
  publisher_id          TEXT,
  campaign_id           TEXT,
  ad_id                 TEXT,
  session_token         TEXT,                      -- opaque, no PII, no mapping to user
  impression_token      TEXT,
  request_id            TEXT,
  surface               TEXT,
  user_agent_hash       TEXT,
  candidate_set_size    INT,
  alert_type            TEXT,
  seq                   BIGINT,
  ingested_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for reporting queries
CREATE INDEX IF NOT EXISTS idx_event_log_type_ts ON event_log(event_type, timestamp_utc_ms);
CREATE INDEX IF NOT EXISTS idx_event_log_publisher ON event_log(publisher_id, timestamp_utc_ms);
CREATE INDEX IF NOT EXISTS idx_event_log_campaign ON event_log(campaign_id, timestamp_utc_ms);
CREATE INDEX IF NOT EXISTS idx_event_log_request_id ON event_log(request_id);       -- deduplication
CREATE INDEX IF NOT EXISTS idx_event_log_impression_token ON event_log(impression_token); -- click join
