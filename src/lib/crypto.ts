/**
 * Cryptographic utilities for Ambient API.
 *
 * Impression token: HMAC-SHA256(impressionTokenSecret, payload)
 * Log record HMAC:  HMAC-SHA256(logSigningKey, canonicalJSON of record)
 * Both keys are env-var injected and MUST be distinct.
 *
 * Spec refs:
 *   AMBIENT_ARCHITECTURE_V1.md §7
 *   SENTINEL_SECURITY_DECISIONS_V1.md Decision 1 + 3
 */
import crypto from 'crypto';
import { config } from './config';

const LOG_SIGNING_KEY = process.env['LOG_SIGNING_KEY'] ?? 'dev-log-signing-key-change-in-prod-32c';

// Advisory (pre-prod gate): fail fast if LOG_SIGNING_KEY is not set in production.
if (process.env['NODE_ENV'] === 'production' && !process.env['LOG_SIGNING_KEY']) {
  throw new Error(
    'FATAL: LOG_SIGNING_KEY environment variable is not set. ' +
    'This key is required for tamper-evident log signing in production. ' +
    'Set LOG_SIGNING_KEY to a secret 32-byte+ value before starting the server.',
  );
}

// ─────────────────────────────────────────────
// Impression token
// ─────────────────────────────────────────────

export interface ImpressionTokenPayload {
  impression_id: string;
  publisher_id: string;
  campaign_id: string;
  timestamp_ms: number;
}

/** Encode payload into a signed opaque token string. */
export function mintImpressionToken(payload: ImpressionTokenPayload): string {
  const data = JSON.stringify({
    i: payload.impression_id,
    p: payload.publisher_id,
    c: payload.campaign_id,
    t: payload.timestamp_ms,
  });
  const encoded = Buffer.from(data).toString('base64url');
  const sig = hmacSha256Hex(config.auth.impressionTokenSecret, encoded);
  return `${encoded}.${sig}`;
}

/**
 * Validate impression token.
 * Sentinel Decision 3: enforce 24h validity window.
 * Returns payload or throws.
 */
export function validateImpressionToken(token: string): ImpressionTokenPayload {
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error('INVALID_TOKEN_FORMAT');
  }
  const [encoded, sig] = parts as [string, string];
  const expectedSig = hmacSha256Hex(config.auth.impressionTokenSecret, encoded);
  if (!timingSafeEqual(sig, expectedSig)) {
    throw new Error('INVALID_TOKEN_SIGNATURE');
  }
  let parsed: { i: string; p: string; c: string; t: number };
  try {
    parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new Error('INVALID_TOKEN_PAYLOAD');
  }
  // Sentinel Decision 3, addition 1: 24h validity window
  const ageMs = Date.now() - parsed.t;
  if (ageMs > 86_400_000) {
    throw new Error('TOKEN_EXPIRED');
  }
  return {
    impression_id: parsed.i,
    publisher_id: parsed.p,
    campaign_id: parsed.c,
    timestamp_ms: parsed.t,
  };
}

// ─────────────────────────────────────────────
// Log record integrity
// Sentinel Decision 1: hash chain + per-record HMAC seal
// ─────────────────────────────────────────────

export const GENESIS_PREV_HASH =
  'sha256:0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Compute SHA-256 of canonical JSON of a record (all fields except record_hmac).
 * Canonical = keys sorted alphabetically, no extra whitespace, UTF-8.
 */
export function canonicalSha256(obj: Record<string, unknown>): string {
  const canonical = canonicalJson(obj);
  return 'sha256:' + crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Compute HMAC-SHA256 over canonical JSON using the log signing key.
 * Excludes the record_hmac field from the input.
 */
export function sealRecord(record: Record<string, unknown>): string {
  const { record_hmac: _excluded, ...rest } = record;
  const canonical = canonicalJson(rest);
  return 'hmac-sha256:' + hmacSha256Hex(LOG_SIGNING_KEY, canonical);
}

// ─────────────────────────────────────────────
// PII detection (Warden + spec requirement: strip/reject context payload PII)
// ─────────────────────────────────────────────

// Conservative patterns. False positives are acceptable — log and reject.
const PII_PATTERNS: RegExp[] = [
  /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/, // email
  /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/,                      // US phone
  /\b\d{3}-\d{2}-\d{4}\b/,                                   // SSN
  /\b(?:\d[ -]?){13,16}\b/,                                  // credit card-like
  // IP addresses — extra caution given GPT Store surfaces
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
];

export function containsPii(keywords: string[]): boolean {
  const joined = keywords.join(' ');
  return PII_PATTERNS.some((re) => re.test(joined));
}

// ─────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────

function hmacSha256Hex(key: string, data: string): string {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest('hex');
}

/**
 * Constant-time string comparison for hex-encoded HMAC values.
 *
 * S-1 (Sentinel): the early-return length check `if (a.length !== b.length) return false`
 * leaks token length via timing.  We must always call crypto.timingSafeEqual regardless
 * of length.  Pad the shorter buffer with zero bytes so both have equal length before the
 * comparison — the result is always false when lengths differ, but timing is constant.
 */
function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  const len = Math.max(bufA.length, bufB.length);
  const paddedA = Buffer.alloc(len, 0);
  const paddedB = Buffer.alloc(len, 0);
  bufA.copy(paddedA);
  bufB.copy(paddedB);
  // Lengths differ → always mismatch, but we never short-circuit before the compare.
  return crypto.timingSafeEqual(paddedA, paddedB) && bufA.length === bufB.length;
}

/** Deterministic JSON serialisation — keys sorted, no extra whitespace. */
function canonicalJson(obj: Record<string, unknown>): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(val: unknown): unknown {
  if (Array.isArray(val)) return val.map(sortKeys);
  if (val !== null && typeof val === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(val as object).sort()) {
      sorted[k] = sortKeys((val as Record<string, unknown>)[k]);
    }
    return sorted;
  }
  return val;
}

/** SHA-256 of arbitrary string — used for click_seen redis key. */
export function sha256Hex(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}
