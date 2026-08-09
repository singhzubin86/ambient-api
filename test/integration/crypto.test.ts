/**
 * Unit tests — crypto.ts
 * Impression token mint/validate, chain integrity, PII detection
 */
import {
  mintImpressionToken,
  validateImpressionToken,
  canonicalSha256,
  sealRecord,
  GENESIS_PREV_HASH,
  containsPii,
  sha256Hex,
} from '../../src/lib/crypto';

describe('Impression token', () => {
  const payload = {
    impression_id: 'imp-001',
    publisher_id: 'pub_abc',
    campaign_id: 'camp_xyz',
    timestamp_ms: Date.now(),
  };

  test('mint produces non-empty token string', () => {
    const token = mintImpressionToken(payload);
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(10);
  });

  test('validate round-trips correctly', () => {
    const token = mintImpressionToken(payload);
    const result = validateImpressionToken(token);
    expect(result.impression_id).toBe(payload.impression_id);
    expect(result.publisher_id).toBe(payload.publisher_id);
    expect(result.campaign_id).toBe(payload.campaign_id);
  });

  test('validate rejects tampered token', () => {
    const token = mintImpressionToken(payload);
    const tampered = token.slice(0, -4) + 'xxxx';
    expect(() => validateImpressionToken(tampered)).toThrow();
  });

  test('validate rejects expired token (>24h old) — Sentinel Decision 3', () => {
    const old = { ...payload, timestamp_ms: Date.now() - 25 * 60 * 60 * 1000 };
    const token = mintImpressionToken(old);
    expect(() => validateImpressionToken(token)).toThrow('TOKEN_EXPIRED');
  });

  test('validate accepts token just under 24h', () => {
    const fresh = { ...payload, timestamp_ms: Date.now() - 23 * 60 * 60 * 1000 };
    const token = mintImpressionToken(fresh);
    expect(() => validateImpressionToken(token)).not.toThrow();
  });
});

describe('Log record chain integrity — Sentinel Decision 1', () => {
  test('canonical SHA-256 is deterministic', () => {
    const obj = { b: 2, a: 1, c: [3, 4] };
    const h1 = canonicalSha256(obj);
    const h2 = canonicalSha256(obj);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  test('canonical SHA-256 changes when any field changes', () => {
    const obj = { a: 1, b: 'hello' };
    const h1 = canonicalSha256(obj);
    const h2 = canonicalSha256({ ...obj, b: 'world' });
    expect(h1).not.toBe(h2);
  });

  test('sealRecord produces deterministic HMAC string', () => {
    const record = { v: 1, seq: 1, event_type: 'impression', prev_hash: GENESIS_PREV_HASH };
    const hmac1 = sealRecord(record as any);
    const hmac2 = sealRecord(record as any);
    expect(hmac1).toBe(hmac2);
    expect(hmac1).toMatch(/^hmac-sha256:[a-f0-9]{64}$/);
  });

  test('sealRecord changes when any field changes (tamper detection)', () => {
    const r1 = { v: 1, seq: 1, event_type: 'impression', prev_hash: GENESIS_PREV_HASH };
    const r2 = { ...r1, seq: 2 };
    expect(sealRecord(r1 as any)).not.toBe(sealRecord(r2 as any));
  });

  test('genesis prev_hash has correct format', () => {
    expect(GENESIS_PREV_HASH).toMatch(/^sha256:0{64}$/);
  });
});

describe('PII detection', () => {
  test('detects email in keywords', () => {
    expect(containsPii(['travel', 'user@example.com'])).toBe(true);
  });

  test('detects US phone number', () => {
    expect(containsPii(['call', '555-867-5309'])).toBe(true);
  });

  test('detects IP address', () => {
    expect(containsPii(['server', '192.168.1.1'])).toBe(true);
  });

  test('clean keywords pass', () => {
    expect(containsPii(['travel', 'hotel', 'europe', 'booking'])).toBe(false);
  });
});

describe('sha256Hex', () => {
  test('produces 64-char hex string', () => {
    const h = sha256Hex('hello');
    expect(h).toMatch(/^[a-f0-9]{64}$/);
  });

  test('deterministic', () => {
    expect(sha256Hex('test')).toBe(sha256Hex('test'));
  });
});
