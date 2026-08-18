/**
 * Integration tests — Publisher self-service (SPEC-3)
 *
 * POST   /v1/portal/publishers            — onboard
 * GET    /v1/portal/publishers/me         — get record
 * POST   /v1/portal/publishers/me/regenerate-key — rotate key
 */
import request from 'supertest';
import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { createApp } from '../../src/index';

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
jest.mock('../../src/lib/email', () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
}));

const mockRedisGet = jest.fn().mockResolvedValue(null);
jest.mock('../../src/db/redis', () => ({
  getRedis: () => ({
    get: mockRedisGet,
    set: jest.fn().mockResolvedValue('OK'),
    quit: jest.fn(),
    pipeline: () => ({ incr: jest.fn(), expire: jest.fn(), exec: jest.fn().mockResolvedValue([]) }),
  }),
  closeRedis: jest.fn(),
}));

const mockQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
const mockConnect = jest.fn();
jest.mock('../../src/db/pool', () => ({
  getPool: () => ({ query: mockQuery, connect: mockConnect }),
  closePool: jest.fn(),
}));

let app: express.Application;
beforeAll(async () => { app = await createApp(); });
beforeEach(() => {
  jest.clearAllMocks();
  mockRedisGet.mockResolvedValue(null);
});

function makePublisherJwt(userId = 'u1', role: 'publisher' | 'advertiser' | 'both' = 'publisher'): string {
  const secret = process.env['JWT_SECRET'] ?? 'dev-jwt-secret-change-in-production-32c';
  return jwt.sign(
    { sub: userId, email: 'alice@company.com', role, jti: crypto.randomBytes(8).toString('hex') },
    secret,
    { expiresIn: 86400 },
  );
}

const validOnboardBody = {
  app_name: 'My AI Assistant',
  app_url: 'https://myapp.example.com',
  app_category: 'standalone_chatbot',
  mau_range: '1k_10k',
  integration_type: 'standalone_web_chatbot',
};

// ── Onboarding ─────────────────────────────────────────────────────────────────
describe('POST /v1/portal/publishers', () => {
  test('401 without portal session', async () => {
    const res = await request(app).post('/v1/portal/publishers').send(validOnboardBody);
    expect(res.status).toBe(401);
  });

  test('403 for advertiser-only role', async () => {
    const token = makePublisherJwt('u1', 'advertiser');
    const res = await request(app).post('/v1/portal/publishers')
      .set('Cookie', `__Host-amb-portal=${token}`)
      .send(validOnboardBody);
    expect(res.status).toBe(403);
  });

  test('422 when required onboarding fields missing', async () => {
    const token = makePublisherJwt();
    const res = await request(app).post('/v1/portal/publishers')
      .set('Cookie', `__Host-amb-portal=${token}`)
      .send({ app_name: 'Test' }); // missing app_url, category, mau_range, integration_type
    expect(res.status).toBe(422);
    expect(res.body.errors).toHaveProperty('app_url');
    expect(res.body.errors).toHaveProperty('app_category');
  });

  test('422 for invalid app_category value', async () => {
    const token = makePublisherJwt();
    const res = await request(app).post('/v1/portal/publishers')
      .set('Cookie', `__Host-amb-portal=${token}`)
      .send({ ...validOnboardBody, app_category: 'invalid_category' });
    expect(res.status).toBe(422);
  });

  test('422 for invalid mau_range value', async () => {
    const token = makePublisherJwt();
    const res = await request(app).post('/v1/portal/publishers')
      .set('Cookie', `__Host-amb-portal=${token}`)
      .send({ ...validOnboardBody, mau_range: 'millions' });
    expect(res.status).toBe(422);
  });

  test('409 when publisher already exists for user', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{ publisher_id: 'pub_existing' }] }); // existing check
    const res = await request(app).post('/v1/portal/publishers')
      .set('Cookie', `__Host-amb-portal=${token}`)
      .send(validOnboardBody);
    expect(res.status).toBe(409);
    expect(res.body.publisher_id).toBe('pub_existing');
  });

  test('201 on successful onboarding — returns api_key once, prefix amb_live_', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [] }); // no existing publisher
    mockQuery.mockResolvedValueOnce({ rows: [{ email: 'alice@company.com', full_name: 'Alice', company_name: 'Co' }] }); // portal user
    const mockClient = {
      query: jest.fn()
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce({ rows: [{
          publisher_id: 'pub_new',
          name: validOnboardBody.app_name,
          contact_email: 'alice@company.com',
          api_key_prefix: 'amb_live_',
          status: 'active',
          app_name: validOnboardBody.app_name,
          app_url: validOnboardBody.app_url,
          app_category: validOnboardBody.app_category,
          mau_range: validOnboardBody.mau_range,
          integration_type: validOnboardBody.integration_type,
          cpm_usd: '5.00',
          created_at: new Date().toISOString(),
        }] }) // INSERT publisher
        .mockResolvedValueOnce(undefined), // COMMIT
      release: jest.fn(),
    };
    mockConnect.mockResolvedValueOnce(mockClient);

    const res = await request(app).post('/v1/portal/publishers')
      .set('Cookie', `__Host-amb-portal=${token}`)
      .send(validOnboardBody);

    expect(res.status).toBe(201);
    expect(res.body.api_key).toBeDefined();
    expect(res.body.api_key).toMatch(/^amb_live_/);
    expect(res.body.publisher_id).toBe('pub_new');
    expect(res.body.cpm_usd).toBe(5.00);
  });
});

// ── GET /v1/portal/publishers/me ─────────────────────────────────────────────────────
describe('GET /v1/portal/publishers/me', () => {
  test('401 without session', async () => {
    const res = await request(app).get('/v1/portal/publishers/me');
    expect(res.status).toBe(401);
  });

  test('404 when no publisher record exists for user', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await request(app).get('/v1/portal/publishers/me')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(404);
  });

  test('200 returns publisher record with masked API key', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{
      publisher_id: 'pub1',
      name: 'My App',
      contact_email: 'alice@company.com',
      api_key_prefix: 'amb_live_',
      status: 'active',
      app_name: 'My AI Assistant',
      app_url: 'https://myapp.example.com',
      app_category: 'standalone_chatbot',
      mau_range: '1k_10k',
      integration_type: 'standalone_web_chatbot',
      cpm_usd: '5.0000',
      created_at: new Date().toISOString(),
    }] });
    const res = await request(app).get('/v1/portal/publishers/me')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(200);
    // Full API key must NOT be present
    expect(res.body.api_key).toBeUndefined();
    expect(res.body.api_key_masked).toBeDefined();
    expect(res.body.publisher_id).toBe('pub1');
    expect(res.body.cpm_usd).toBe(5.00);
  });
});

// ── POST /v1/portal/publishers/me/regenerate-key ─────────────────────────────────────
describe('POST /v1/portal/publishers/me/regenerate-key', () => {
  test('401 without session', async () => {
    const res = await request(app).post('/v1/portal/publishers/me/regenerate-key');
    expect(res.status).toBe(401);
  });

  test('404 when no active publisher record', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await request(app).post('/v1/portal/publishers/me/regenerate-key')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(404);
  });

  test('200 returns new api_key with amb_live_ prefix', async () => {
    const token = makePublisherJwt();
    mockQuery
      .mockResolvedValueOnce({ rows: [{ publisher_id: 'pub1' }] }) // find publisher
      .mockResolvedValueOnce({ rows: [], rowCount: 1 });             // update key
    const res = await request(app).post('/v1/portal/publishers/me/regenerate-key')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.api_key).toMatch(/^amb_live_/);
    expect(res.body.publisher_id).toBe('pub1');
    // Verify key is long enough (prefix + base58 of 32 bytes)
    expect(res.body.api_key.length).toBeGreaterThan(20);
  });
});
