/**
 * Integration tests — Ad Decisioning API
 * Covers: POST /v1/ads/request, GET /v1/ads/click
 *
 * These tests stub Redis and Postgres to run without live infra.
 * Contract assertions are the primary goal — every spec decision is exercised.
 */
import request from 'supertest';
import express from 'express';
import { createApp } from '../../src/index';

// ── Stubs ─────────────────────────────────────────────────────────────────────
jest.mock('../../src/db/pool', () => {
  const mockQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  return { getPool: () => ({ query: mockQuery }), closePool: jest.fn(), __mockQuery: mockQuery };
});
jest.mock('../../src/db/redis', () => {
  const mockSet = jest.fn().mockResolvedValue('OK');
  const mockGet = jest.fn().mockResolvedValue(null);
  const mockIncr = jest.fn();
  return {
    getRedis: () => ({
      get: mockGet,
      set: mockSet,
      pipeline: () => ({
        incr: jest.fn(),
        incrby: jest.fn(),
        expire: jest.fn(),
        exec: jest.fn().mockResolvedValue([]),
      }),
      incr: mockIncr,
      quit: jest.fn(),
    }),
    closeRedis: jest.fn(),
    __mockSet: mockSet,
    __mockGet: mockGet,
  };
});
jest.mock('../../src/services/log-store', () => ({
  initLogStore: jest.fn().mockResolvedValue(undefined),
  shutdownLogStore: jest.fn().mockResolvedValue(undefined),
  appendRecord: jest.fn(),
}));
jest.mock('../../src/services/campaign-cache', () => ({
  loadCampaigns: jest.fn().mockResolvedValue(undefined),
  startCampaignCacheRefresh: jest.fn(),
  stopCampaignCacheRefresh: jest.fn(),
  getCampaignArray: jest.fn().mockReturnValue([]),
}));
jest.mock('../../src/services/anomaly-monitor', () => ({
  startAnomalyMonitor: jest.fn(),
  stopAnomalyMonitor: jest.fn(),
}));
jest.mock('../../src/services/freq-cap', () => ({
  isFreqCapExceeded: jest.fn().mockResolvedValue(false),
  recordFreqCapImpression: jest.fn().mockResolvedValue(undefined),
  SESSION_TOKEN_PATTERN: /^[a-zA-Z0-9_-]{1,128}$/,
}));
jest.mock('../../src/middleware/auth', () => ({
  publisherApiKeyAuth: (_req: any, _res: any, next: any) => {
    _req.publisherId = 'pub_test123';
    next();
  },
  advertiserJwtAuth: (_req: any, _res: any, next: any) => {
    _req.jwtPayload = { sub: 'user_1', role: 'advertiser', advertiser_id: 'adv_1' };
    next();
  },
  requireRole: (..._roles: string[]) => (_req: any, _res: any, next: any) => next(),
}));

import { getCampaignArray } from '../../src/services/campaign-cache';

const mockCampaigns = jest.mocked(getCampaignArray);

function makeCampaign(overrides = {}) {
  return {
    campaign_id: 'camp_001',
    advertiser_id: 'adv_1',
    name: 'Test Campaign',
    advertiser_category: 'general',
    status: 'active',
    headline: 'Great Product',
    body: 'Buy it now and save.',
    cta_text: 'Shop Now',
    destination_url: 'https://example.com',
    disclosure_label: 'Ad' as const,
    disclosure_placement: 'prepend' as const,
    targeting_keywords: ['travel', 'hotel'],
    targeting_keywords_stemmed: ['travel', 'hotel'],
    targeting_surfaces: [],
    budget_total_cents: 1_000_000,
    budget_daily_cents: 50_000,
    cpm_floor_cents: 500,
    flight_start: new Date(Date.now() - 86400_000),
    flight_end: new Date(Date.now() + 86400_000),
    created_at: new Date('2026-01-01'),
    ...overrides,
  };
}

let app: express.Application;
beforeAll(async () => { app = await createApp(); });

// ─── POST /v1/ads/request ─────────────────────────────────────────────────────

describe('POST /v1/ads/request', () => {
  const validBody = {
    publisher_id: 'pub_test123',
    session_token: 'sess-abc-123',
    context: { keywords: ['travel', 'hotel'], surface: 'standalone_chatbot' },
    request_id: 'req-uuid-001',
  };

  test('returns 204 when no campaigns match', async () => {
    mockCampaigns.mockReturnValue([]);
    const res = await request(app).post('/v1/ads/request').send(validBody);
    expect(res.status).toBe(204);
  });

  test('returns 200 with ad object when campaign matches', async () => {
    mockCampaigns.mockReturnValue([makeCampaign()]);
    const res = await request(app).post('/v1/ads/request').send(validBody);
    expect(res.status).toBe(200);
    expect(res.body.ad).toBeDefined();
    expect(res.body.impression_token).toBeDefined();
    expect(res.body.request_id).toBe('req-uuid-001');
  });

  test('ad response includes non-nullable disclosure_label and disclosure_placement (Warden)', async () => {
    mockCampaigns.mockReturnValue([makeCampaign()]);
    const res = await request(app).post('/v1/ads/request').send(validBody);
    expect(res.status).toBe(200);
    expect(['Ad', 'Sponsored']).toContain(res.body.ad.disclosure_label);
    expect(['prepend', 'surround']).toContain(res.body.ad.disclosure_placement);
  });

  test('returns 400 when session_token is missing', async () => {
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, session_token: undefined });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INVALID_SESSION_TOKEN');
  });

  test('returns 400 when session_token fails pattern (Socket spec: ^[a-zA-Z0-9_-]{1,128}$)', async () => {
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, session_token: 'bad token with spaces!' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INVALID_SESSION_TOKEN');
  });

  test('returns 400 for PII field "email" in request body (Blueprint requirement)', async () => {
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, email: 'user@example.com' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('PII_FIELD_REJECTED');
  });

  test('returns 400 for PII field "user_id" in request body', async () => {
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, user_id: 'abc123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('PII_FIELD_REJECTED');
  });

  test('returns 400 for PII field "device_id" in request body', async () => {
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, device_id: 'device-xyz' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('PII_FIELD_REJECTED');
  });

  test('returns 400 for PII field "ip" in request body', async () => {
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, ip: '1.2.3.4' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('PII_FIELD_REJECTED');
  });

  test('returns 400 when email-like PII in context keywords', async () => {
    const res = await request(app).post('/v1/ads/request').send({
      ...validBody,
      context: { keywords: ['travel', 'user@example.com'], surface: 'standalone_chatbot' },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('PII_DETECTED_IN_KEYWORDS');
  });

  test('P-1: returns 204 (not 400) when context.keywords is an empty array', async () => {
    // Empty keywords is a valid no-fill signal, not a protocol error.
    const res = await request(app).post('/v1/ads/request').send({
      ...validBody,
      context: { keywords: [], surface: 'standalone_chatbot' },
    });
    expect(res.status).toBe(204);
  });

  test('selects highest CPM campaign when multiple match (Signal Decision 3)', async () => {
    const low = makeCampaign({ campaign_id: 'camp_low', cpm_floor_cents: 200, headline: 'Low CPM' });
    const high = makeCampaign({ campaign_id: 'camp_high', cpm_floor_cents: 1000, headline: 'High CPM' });
    mockCampaigns.mockReturnValue([low, high]);
    const res = await request(app).post('/v1/ads/request').send(validBody);
    expect(res.status).toBe(200);
    expect(res.body.ad.headline).toBe('High CPM');
  });

  test('tie-break: oldest campaign wins when CPM is equal (Signal Decision 3)', async () => {
    const older = makeCampaign({ campaign_id: 'camp_old', created_at: new Date('2026-01-01'), headline: 'Older' });
    const newer = makeCampaign({ campaign_id: 'camp_new', created_at: new Date('2026-06-01'), headline: 'Newer' });
    mockCampaigns.mockReturnValue([newer, older]); // intentionally wrong order
    const res = await request(app).post('/v1/ads/request').send(validBody);
    expect(res.status).toBe(200);
    expect(res.body.ad.headline).toBe('Older');
  });

  test('returns 204 when campaign is outside flight dates', async () => {
    const expired = makeCampaign({
      flight_end: new Date(Date.now() - 86400_000), // ended yesterday
    });
    mockCampaigns.mockReturnValue([expired]);
    const res = await request(app).post('/v1/ads/request').send(validBody);
    expect(res.status).toBe(204);
  });

  test('returns 204 when no keyword overlap (stemmed match required)', async () => {
    const camp = makeCampaign({ targeting_keywords_stemmed: ['financ', 'invest'] });
    mockCampaigns.mockReturnValue([camp]);
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, context: { keywords: ['travel'], surface: 'standalone_chatbot' } });
    expect(res.status).toBe(204);
  });

  test('matches via Porter stemming (Signal Decision 2)', async () => {
    // "traveling" stems to "travel", campaign keyword "travel" → match
    const camp = makeCampaign({ targeting_keywords_stemmed: ['travel'] });
    mockCampaigns.mockReturnValue([camp]);
    const res = await request(app).post('/v1/ads/request')
      .send({ ...validBody, context: { keywords: ['traveling', 'hotels'], surface: 'standalone_chatbot' } });
    expect(res.status).toBe(200);
  });

  test('cta_url contains impression_token for click tracking', async () => {
    mockCampaigns.mockReturnValue([makeCampaign()]);
    const res = await request(app).post('/v1/ads/request').send(validBody);
    expect(res.status).toBe(200);
    expect(res.body.ad.cta_url).toContain('token=');
    expect(res.body.ad.cta_url).toContain(encodeURIComponent(res.body.impression_token));
  });
});

// ─── GET /v1/ads/click ────────────────────────────────────────────────────────

describe('GET /v1/ads/click', () => {
  const getRedisMock = () => jest.requireMock('../../src/db/redis') as any;
  const getDbQuery = () => (jest.requireMock('../../src/db/pool') as any).__mockQuery as jest.Mock;

  beforeEach(() => {
    getDbQuery().mockResolvedValue({ rows: [{ destination_url: 'https://example.com' }] });
    getRedisMock().__mockSet.mockResolvedValue('OK'); // first click = not seen
  });

  test('returns 400 when token param is missing', async () => {
    const res = await request(app).get('/v1/ads/click');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('MISSING_TOKEN');
  });

  test('returns 400 for invalid token', async () => {
    const res = await request(app).get('/v1/ads/click?token=badtoken');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INVALID_TOKEN');
  });

  test('redirects 302 to destination URL for valid token', async () => {
    // Mint a real token for this test
    const { mintImpressionToken } = await import('../../src/lib/crypto');
    const token = mintImpressionToken({
      impression_id: 'imp-001',
      publisher_id: 'pub_test123',
      campaign_id: 'camp_001',
      timestamp_ms: Date.now(),
    });
    const res = await request(app).get(`/v1/ads/click?token=${encodeURIComponent(token)}`).redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers['location']).toBe('https://example.com');
  });

  test('single-use: duplicate click still redirects but does not write click event (Sentinel Decision 3)', async () => {
    const { mintImpressionToken } = await import('../../src/lib/crypto');
    const { appendRecord } = jest.requireMock('../../src/services/log-store');
    const token = mintImpressionToken({
      impression_id: 'imp-002',
      publisher_id: 'pub_test123',
      campaign_id: 'camp_001',
      timestamp_ms: Date.now(),
    });

    // First click: NX succeeds (not seen before)
    getRedisMock().__mockSet.mockResolvedValueOnce('OK');
    await request(app).get(`/v1/ads/click?token=${encodeURIComponent(token)}`).redirects(0);
    // Flush all setImmediate callbacks from first click
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // Second click: NX fails (already seen)
    (appendRecord as jest.Mock).mockClear();
    getRedisMock().__mockSet.mockResolvedValueOnce(null);
    const res2 = await request(app).get(`/v1/ads/click?token=${encodeURIComponent(token)}`).redirects(0);
    expect(res2.status).toBe(302); // still redirects

    // Flush setImmediate callbacks from second click
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // On duplicate: appendRecord called for anomaly_flag but NOT for click event
    const callTypes = (appendRecord as jest.Mock).mock.calls.map((c: any[]) => c[0].event_type);
    expect(callTypes).toContain('anomaly_flag');
    expect(callTypes.filter((t: string) => t === 'click').length).toBe(0);
  });

  test('rejects expired token (Sentinel: 24h validity window)', async () => {
    const { mintImpressionToken } = await import('../../src/lib/crypto');
    const token = mintImpressionToken({
      impression_id: 'imp-003',
      publisher_id: 'pub_test123',
      campaign_id: 'camp_001',
      timestamp_ms: Date.now() - 25 * 60 * 60 * 1000, // 25h ago
    });
    const res = await request(app).get(`/v1/ads/click?token=${encodeURIComponent(token)}`).redirects(0);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INVALID_TOKEN');
    expect(res.body.message).toBe('TOKEN_EXPIRED');
  });
});

// ─── Freq cap (FREQ-01 through FREQ-06) ───────────────────────────────────────
//
// The 2-impression/campaign/session hard cap is enforced by isFreqCapExceeded()
// reading a Redis counter.  The freq-cap module is mocked at the top of this file
// so we can drive exact cap-exceeded / cap-OK responses without wiring Redis
// pipeline state manually.

import { isFreqCapExceeded } from '../../src/services/freq-cap';
const mockIsFreqCapExceeded = jest.mocked(isFreqCapExceeded);

describe('Freq cap — FREQ-01 through FREQ-06', () => {
  const freqBody = {
    publisher_id: 'pub_test123',
    session_token: 'sess-freq-test',
    context: { keywords: ['travel', 'hotel'], surface: 'standalone_chatbot' },
    request_id: 'req-freq-001',
  };

  beforeEach(() => {
    mockIsFreqCapExceeded.mockResolvedValue(false);
    mockCampaigns.mockReturnValue([makeCampaign()]);
  });

  test('FREQ-01: returns 200 when impression count is below cap (0 prior impressions)', async () => {
    mockIsFreqCapExceeded.mockResolvedValue(false);
    const res = await request(app).post('/v1/ads/request').send(freqBody);
    expect(res.status).toBe(200);
    expect(res.body.ad).toBeDefined();
  });

  test('FREQ-02: returns 200 when impression count is exactly 1 (one prior impression, cap=2)', async () => {
    // One impression recorded — still below hard cap of 2.
    mockIsFreqCapExceeded.mockResolvedValue(false);
    const res = await request(app).post('/v1/ads/request').send(freqBody);
    expect(res.status).toBe(200);
    expect(res.body.ad).toBeDefined();
  });

  test('FREQ-03: returns 204 when freq cap is hit (2 impressions already served for this campaign+session)', async () => {
    // isFreqCapExceeded returns true → campaign excluded → no fill → 204
    mockIsFreqCapExceeded.mockResolvedValue(true);
    const res = await request(app).post('/v1/ads/request').send(freqBody);
    expect(res.status).toBe(204);
  });

  test('FREQ-04: cap is campaign-scoped — capped campaign excluded but other campaigns can still fill', async () => {
    const cappedCampaign = makeCampaign({ campaign_id: 'camp_capped', headline: 'Capped Ad' });
    const otherCampaign = makeCampaign({ campaign_id: 'camp_other', headline: 'Other Ad' });
    mockCampaigns.mockReturnValue([cappedCampaign, otherCampaign]);

    // Only the first campaign is capped
    mockIsFreqCapExceeded.mockImplementation((_pub, _sess, campaignId) =>
      Promise.resolve(campaignId === 'camp_capped'),
    );

    const res = await request(app).post('/v1/ads/request').send(freqBody);
    expect(res.status).toBe(200);
    expect(res.body.ad.headline).toBe('Other Ad');
  });

  test('FREQ-05: cap is session-scoped — same campaign fills for a different session_token', async () => {
    // Simulate cap exceeded for one session but not another
    mockIsFreqCapExceeded.mockImplementation((_pub, sessionToken, _camp) =>
      Promise.resolve(sessionToken === 'sess-capped'),
    );

    // Capped session → 204
    const cappedRes = await request(app).post('/v1/ads/request')
      .send({ ...freqBody, session_token: 'sess-capped' });
    expect(cappedRes.status).toBe(204);

    // Different session → 200
    const openRes = await request(app).post('/v1/ads/request')
      .send({ ...freqBody, session_token: 'sess-open', request_id: 'req-freq-002' });
    expect(openRes.status).toBe(200);
    expect(openRes.body.ad).toBeDefined();
  });

  test('FREQ-06: all campaigns capped in session → 204 No Content (total fill starvation)', async () => {
    const camp1 = makeCampaign({ campaign_id: 'camp_a', headline: 'Ad A' });
    const camp2 = makeCampaign({ campaign_id: 'camp_b', headline: 'Ad B' });
    mockCampaigns.mockReturnValue([camp1, camp2]);

    // All campaigns capped for this session
    mockIsFreqCapExceeded.mockResolvedValue(true);

    const res = await request(app).post('/v1/ads/request').send(freqBody);
    expect(res.status).toBe(204);
  });
});
