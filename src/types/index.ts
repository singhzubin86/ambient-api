/**
 * Ambient API — Core Types
 * Spec ref: AMBIENT_ARCHITECTURE_V1.md §5, §4
 */

// ─────────────────────────────────────────────
// Ad Request / Response (publisher-facing)
// ─────────────────────────────────────────────

export type AdSurface = 'gpt_store_custom_gpt' | 'standalone_chatbot';

export interface AdRequestBody {
  publisher_id: string;
  session_token: string;       // opaque, publisher-generated, no PII
  context: {
    keywords: string[];        // extracted publisher-side from conversation — no transcript
    surface: AdSurface;
  };
  request_id: string;          // UUIDv4 — idempotency + log correlation
}

/** Warden additions (mandatory per Relay brief 2026-08-09) */
export type DisclosureLabel = 'Ad' | 'Sponsored';
export type DisclosurePlacement = 'prepend' | 'surround';

export interface AdObject {
  ad_id: string;               // unique per impression; echoed in logs for correlation (SPEC-4 R3)
  headline: string;
  body: string;
  cta_text: string;
  cta_url: string;             // click tracking URL with impression_token embedded
  // Warden-required disclosure fields — non-nullable
  disclosure_label: DisclosureLabel;
  disclosure_placement: DisclosurePlacement;
}

export interface AdResponseHit {
  ad: AdObject;
  impression_token: string;    // HMAC-SHA256 signed
  request_id: string;
}

// 204 No Content = no fill — no body

// ─────────────────────────────────────────────
// Campaign (advertiser-facing)
// ─────────────────────────────────────────────

/**
 * Advertiser categories.
 * Blocked: hard-reject at API layer (Warden requirement).
 * Conditional: route to manual review queue.
 */
export const BLOCKED_ADVERTISER_CATEGORIES = [
  'pharma_rx',
  'investment_securities',
  'gambling',
  'cannabis',
  'political',
  'adult',
] as const;

export const CONDITIONAL_ADVERTISER_CATEGORIES = [
  'alcohol',
  'firearms',
  'financial_services',
  'healthcare_general',
] as const;

export type BlockedAdvertiserCategory = typeof BLOCKED_ADVERTISER_CATEGORIES[number];
export type ConditionalAdvertiserCategory = typeof CONDITIONAL_ADVERTISER_CATEGORIES[number];
export type AdvertiserCategory =
  | BlockedAdvertiserCategory
  | ConditionalAdvertiserCategory
  | 'general';

export type CampaignStatus = 'draft' | 'pending_review' | 'active' | 'paused' | 'completed';

export interface CampaignCreative {
  headline: string;            // max 60 chars
  body: string;                // max 150 chars
  cta_text: string;            // max 20 chars
  destination_url: string;
  // Warden-required — must be set at campaign creation, non-nullable
  disclosure_label: DisclosureLabel;
  disclosure_placement: DisclosurePlacement;
}

export interface CampaignTargeting {
  keywords: string[];          // matched against request.context.keywords (Signal specs semantics)
  surfaces?: AdSurface[];      // if empty: all surfaces
}

export interface Campaign {
  campaign_id: string;
  advertiser_id: string;
  name: string;
  advertiser_category: AdvertiserCategory;  // Warden-required — non-nullable
  status: CampaignStatus;
  creative: CampaignCreative;
  targeting: CampaignTargeting;
  budget_total_cents: number;  // lifetime budget in USD cents
  budget_daily_cents: number;  // daily cap in USD cents
  flight_start: Date;
  flight_end: Date;
  created_at: Date;
  updated_at: Date;
}

export interface CreateCampaignRequest {
  name: string;
  advertiser_category: AdvertiserCategory;  // required — non-nullable
  creative: CampaignCreative;
  targeting: CampaignTargeting;
  budget_total_cents: number;
  budget_daily_cents: number;
  flight_start: string;        // ISO 8601
  flight_end: string;
}

export interface UpdateCampaignRequest {
  name?: string;
  creative?: Partial<CampaignCreative>;
  targeting?: CampaignTargeting;
  budget_total_cents?: number;
  budget_daily_cents?: number;
  flight_start?: string;
  flight_end?: string;
  status?: Extract<CampaignStatus, 'paused' | 'active'>;
}

// ─────────────────────────────────────────────
// Publisher / API Key
// ─────────────────────────────────────────────

export interface Publisher {
  publisher_id: string;
  name: string;
  contact_email: string;       // stored only in publisher record, NOT in ad path
  api_key_prefix: string;      // first 8 chars of key (for display)
  status: 'active' | 'suspended';
  created_at: Date;
}

export interface CreatePublisherRequest {
  name: string;
  contact_email: string;
}

export interface ProvisionApiKeyResponse {
  publisher_id: string;
  api_key: string;             // full key — shown once only
  api_key_prefix: string;
}

// ─────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────

export type UserRole = 'advertiser' | 'publisher' | 'admin';

export interface AdvertiserUser {
  user_id: string;
  email: string;
  role: 'advertiser';
  advertiser_id: string;
  created_at: Date;
}

export interface JwtPayload {
  sub: string;                 // user_id
  role: UserRole;
  advertiser_id?: string;
  iat: number;
  exp: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  expires_in: number;          // seconds
  role: UserRole;
}

// ─────────────────────────────────────────────
// Impression / Click Log
// NOTE: Schema intentionally incomplete pending:
//   1. Sentinel tamper-evidence spec (log format + hash chain)
//   2. Blueprint session token de-linkage confirmation
// Do NOT finalize until both are resolved.
// ─────────────────────────────────────────────

export type LogEventType = 'impression' | 'click' | 'anomaly_flag';

export interface ImpressionLogRecord {
  event_type: 'impression';
  timestamp_utc_ms: number;
  publisher_id: string;
  campaign_id: string;
  ad_id: string;               // creative identifier
  session_token: string;       // opaque — de-linkage architecture TBD (Blueprint open item)
  impression_token: string;    // HMAC-signed — enables click correlation
  request_id: string;
  surface: AdSurface;
  user_agent_hash: string;     // one-way hash — no raw UA stored
  // TODO: add tamper-evidence field once Sentinel specifies (hash chain or record checksum)
}

export interface ClickLogRecord {
  event_type: 'click';
  timestamp_utc_ms: number;
  impression_token: string;    // foreign key to impression record
  publisher_id: string;
  campaign_id: string;
  // TODO: add tamper-evidence field once Sentinel specifies
}

// ─────────────────────────────────────────────
// Reporting
// ─────────────────────────────────────────────

export interface ReportingQuery {
  campaign_id?: string;
  publisher_id?: string;
  start_date: string;          // ISO 8601 date
  end_date: string;
  format?: 'json' | 'csv';
}

export interface ReportingRow {
  date: string;
  campaign_id: string;
  publisher_id: string;
  impressions: number;
  clicks: number;
  ctr: number;                 // clicks / impressions
  spend_cents: number;
}

export interface ReportingSummary {
  total_impressions: number;
  total_clicks: number;
  overall_ctr: number;
  total_spend_cents: number;
  rows: ReportingRow[];
}

// ─────────────────────────────────────────────
// API Error
// ─────────────────────────────────────────────

export interface ApiError {
  error: string;
  message: string;
  code?: string;
  request_id?: string;
}

// Warden-required rejection response for blocked categories
export interface BlockedCategoryError extends ApiError {
  error: 'BLOCKED_ADVERTISER_CATEGORY';
  category: BlockedAdvertiserCategory;
}
