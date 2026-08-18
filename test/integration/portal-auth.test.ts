/**
 * Integration tests — Portal Auth (SPEC-1 + SPEC-2)
 *
 * Endpoints:
 *   POST   /v1/portal/auth/signup
 *   POST   /v1/portal/auth/login
 *   GET    /v1/portal/auth/me
 *   POST   /v1/portal/auth/logout
 *   GET    /v1/portal/auth/verify-email
 *   POST   /v1/portal/auth/resend-verification
 */
import request from 'supertest';
import express from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { createApp } from '../../src/index';
import { generateVerificationToken } from '../../src/lib/portal-auth';

// ── Stubs ──────────────────────────────────────────────────────────────────────
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

// Redis mock — captures denylist calls
const mockRedisGet = jest.fn();
const mockRedisSet = jest.fn();
jest.mock('../../src/db/redis', () => ({
  getRedis: () => ({
    get: mockRedisGet,
    set: mockRedisSet,
    quit: jest.fn(),
    pipeline: () => ({ incr: jest.fn(), expire: jest.fn(), exec: jest.fn().mockResolvedValue([]) }),
  }),
  closeRedis: jest.fn(),
}));

// DB mock — each test sets up its own sequence
const mockQuery = jest.fn();
const mockConnect = jest.fn();
jest.mock('../../src/db/pool', () => ({
  getPool: () => ({ query: mockQuery, connect: mockConnect }),
  closePool: jest.fn(),
}));

import * as emailLib from '../../src/lib/email';
const mockSendEmail = emailLib.sendVerificationEmail as jest.Mock;

let app: express.Application;
beforeAll(async () => { app = await createApp(); });
beforeEach(() => {
  // Full reset of all mocks between tests to eliminate state leaks
  mockQuery.mockReset();
  mockConnect.mockReset();
  mockRedisGet.mockReset();
  mockRedisSet.mockReset();
  mockSendEmail.mockReset();
  // Defaults
  mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
  mockRedisGet.mockResolvedValue(null);
  mockRedisSet.mockResolvedValue('OK');
  mockSendEmail.mockResolvedValue(undefined);
});

// ── Signup ─────────────────────────────────────────────────────────────────────
describe('POST /v1/portal/auth/signup', () => {
  const validBody = {
    full_name: 'Alice Test',
    email: 'alice@company.com',
    company_name: 'Company Inc',
    password: 'supersecurepass1',
    role: 'publisher',
  };

  test('422 when required fields missing', async () => {
    const res = await request(app).post('/v1/portal/auth/signup').send({});
    expect(res.status).toBe(422);
    expect(res.body.error).toBe('VALIDATION_ERROR');
    expect(res.body.errors).toHaveProperty('email');
    expect(res.body.errors).toHaveProperty('password');
  });

  test('422 for consumer email domain (gmail)', async () => {
    const res = await request(app).post('/v1/portal/auth/signup')
      .send({ ...validBody, email: 'alice@gmail.com' });
    expect(res.status).toBe(422);
    expect(res.body.errors.email).toMatch(/business email/i);
  });

  test('422 for password shorter than 12 chars', async () => {
    const res = await request(app).post('/v1/portal/auth/signup')
      .send({ ...validBody, password: 'short' });
    expect(res.status).toBe(422);
    expect(res.body.errors.password).toMatch(/12/);
  });

  test('422 for invalid role value', async () => {
    const res = await request(app).post('/v1/portal/auth/signup')
      .send({ ...validBody, role: 'superadmin' });
    expect(res.status).toBe(422);
  });

  test('409 when email already exists', async () => {
    // existing user check returns a row
    mockQuery.mockResolvedValueOnce({ rows: [{ user_id: 'existing' }] });
    const res = await request(app).post('/v1/portal/auth/signup').send(validBody);
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('CONFLICT');
  });

  test('201 on successful signup — sends verification email', async () => {
    // existing check → none
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const mockClient = {
      query: jest.fn()
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce({ rows: [{ user_id: 'u1', email: 'alice@company.com', role: 'publisher', status: 'pending_verification' }] }) // INSERT user
        .mockResolvedValueOnce({ rows: [] }) // INSERT token
        .mockResolvedValueOnce(undefined), // COMMIT
      release: jest.fn(),
    };
    mockConnect.mockResolvedValueOnce(mockClient);

    const res = await request(app).post('/v1/portal/auth/signup').send(validBody);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ email: 'alice@company.com', role: 'publisher', status: 'pending_verification' });
    expect(mockSendEmail).toHaveBeenCalledWith(expect.objectContaining({ to: 'alice@company.com' }));
  });

  test('signup still returns 201 even if email send fails', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const mockClient = {
      query: jest.fn()
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce({ rows: [{ user_id: 'u2', email: 'alice@company.com', role: 'publisher', status: 'pending_verification' }] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce(undefined),
      release: jest.fn(),
    };
    mockConnect.mockResolvedValueOnce(mockClient);
    mockSendEmail.mockRejectedValueOnce(new Error('Resend API error'));

    const res = await request(app).post('/v1/portal/auth/signup').send(validBody);
    expect(res.status).toBe(201);
  });
});

// ── Login ──────────────────────────────────────────────────────────────────────
describe('POST /v1/portal/auth/login', () => {
  const loginBody = { email: 'alice@company.com', password: 'supersecurepass1' };

  test('400 when email or password missing', async () => {
    const res = await request(app).post('/v1/portal/auth/login').send({ email: 'a@b.com' });
    expect(res.status).toBe(400);
  });

  test('401 for unknown email', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await request(app).post('/v1/portal/auth/login').send(loginBody);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('UNAUTHORIZED');
  });

  test('401 for wrong password', async () => {
    const hash = await bcrypt.hash('differentpass', 10);
    mockQuery.mockResolvedValueOnce({
      rows: [{ user_id: 'u1', email: loginBody.email, full_name: 'Alice', company_name: 'Co', role: 'publisher', password_hash: hash, verified: true, status: 'active' }],
    });
    const res = await request(app).post('/v1/portal/auth/login').send(loginBody);
    expect(res.status).toBe(401);
  });

  test('403 when email not verified', async () => {
    const hash = await bcrypt.hash(loginBody.password, 10);
    mockQuery.mockResolvedValueOnce({
      rows: [{ user_id: 'u1', email: loginBody.email, full_name: 'Alice', company_name: 'Co', role: 'publisher', password_hash: hash, verified: false, status: 'pending_verification' }],
    });
    const res = await request(app).post('/v1/portal/auth/login').send(loginBody);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('email_not_verified');
  });

  test('403 for suspended account', async () => {
    const hash = await bcrypt.hash(loginBody.password, 10);
    mockQuery.mockResolvedValueOnce({
      rows: [{ user_id: 'u1', email: loginBody.email, full_name: 'Alice', company_name: 'Co', role: 'publisher', password_hash: hash, verified: true, status: 'suspended' }],
    });
    const res = await request(app).post('/v1/portal/auth/login').send(loginBody);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('ACCOUNT_SUSPENDED');
  });

  test('200 on successful login — sets HttpOnly cookie', async () => {
    const hash = await bcrypt.hash(loginBody.password, 10);
    mockQuery.mockResolvedValueOnce({
      rows: [{ user_id: 'u1', email: loginBody.email, full_name: 'Alice', company_name: 'Co', role: 'publisher', password_hash: hash, verified: true, status: 'active' }],
    });
    const res = await request(app).post('/v1/portal/auth/login').send(loginBody);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ email: loginBody.email, role: 'publisher' });
    // Password hash must not be in response
    expect(res.body).not.toHaveProperty('password_hash');

    // Cookie must be HttpOnly with the right name
    const setCookieHeader = res.headers['set-cookie'];
    const cookieStr = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader ?? '';
    expect(cookieStr).toMatch(/HttpOnly/i);
    expect(cookieStr).toMatch(/__Host-amb-portal/);
  });
});

// ── Me ─────────────────────────────────────────────────────────────────────────
describe('GET /v1/portal/auth/me', () => {
  function makePortalJwt(userId = 'u1', role: 'publisher' | 'advertiser' | 'both' = 'publisher'): string {
    const secret = process.env['JWT_SECRET'] ?? 'dev-jwt-secret-change-in-production-32c';
    return jwt.sign({ sub: userId, email: 'alice@company.com', role, jti: crypto.randomBytes(8).toString('hex') }, secret, { expiresIn: 86400 });
  }

  test('401 with no cookie', async () => {
    const res = await request(app).get('/v1/portal/auth/me');
    expect(res.status).toBe(401);
  });

  test('401 with denylisted token (simulated logout)', async () => {
    const token = makePortalJwt();
    mockRedisGet.mockResolvedValueOnce('1'); // denylisted
    const res = await request(app).get('/v1/portal/auth/me')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(401);
  });

  test('200 returns user info for valid session — no password_hash', async () => {
    const token = makePortalJwt();
    // mockRedisGet returns null (not denylisted) by default from beforeEach
    // DB returns only the columns the SELECT picks
    mockQuery.mockResolvedValueOnce({
      rows: [{ user_id: 'u1', email: 'alice@company.com', full_name: 'Alice', company_name: 'Co', role: 'publisher', verified: true }],
    });
    const res = await request(app).get('/v1/portal/auth/me')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ email: 'alice@company.com', role: 'publisher' });
    // DB mock only returns what the SELECT specifies — no password_hash in the response
    expect(res.body).not.toHaveProperty('password_hash');
  });
});

// ── Logout ─────────────────────────────────────────────────────────────────────
describe('POST /v1/portal/auth/logout', () => {
  function makePortalJwtWithJti(jti: string, userId = 'u1'): string {
    const secret = process.env['JWT_SECRET'] ?? 'dev-jwt-secret-change-in-production-32c';
    return jwt.sign({ sub: userId, email: 'a@b.com', role: 'publisher', jti }, secret, { expiresIn: 86400 });
  }

  test('401 without session cookie', async () => {
    const res = await request(app).post('/v1/portal/auth/logout');
    expect(res.status).toBe(401);
  });

  test('204 on logout — denylists jti in Redis + clears cookie', async () => {
    const jti = 'testjti-' + crypto.randomBytes(4).toString('hex');
    const token = makePortalJwtWithJti(jti);
    // Not denylisted check in portalAuth middleware
    mockRedisGet.mockResolvedValueOnce(null);
    const res = await request(app).post('/v1/portal/auth/logout')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(204);
    // Redis SET was called to denylist jti
    expect(mockRedisSet).toHaveBeenCalledWith(
      `jwt_deny:${jti}`,
      '1',
      'EX',
      expect.any(Number),
    );
    // Cookie cleared
    const setCookieHeader = res.headers['set-cookie'];
    const cookieStr = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader ?? '';
    expect(cookieStr).toMatch(/__Host-amb-portal=/);
  });
});

// ── Email Verification ─────────────────────────────────────────────────────────
describe('GET /v1/portal/auth/verify-email', () => {
  test('302 to /verify-email?error=missing when no token', async () => {
    const res = await request(app).get('/v1/portal/auth/verify-email');
    expect(res.status).toBe(302);
    expect(res.headers['location']).toMatch(/error=missing/);
  });

  test('302 to /verify-email?error=invalid for unknown token', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] }); // token not found
    const { raw } = generateVerificationToken();
    const res = await request(app).get(`/v1/portal/auth/verify-email?token=${raw}`);
    expect(res.status).toBe(302);
    expect(res.headers['location']).toMatch(/error=invalid/);
  });

  test('302 to /verify-email?error=invalid for already-used token (used_at set)', async () => {
    const { raw } = generateVerificationToken();
    // Route checks used_at first — if used_at is set, returns invalid immediately
    mockQuery.mockResolvedValueOnce({
      rows: [{ token_id: 't1', user_id: 'u1', expires_at: new Date(Date.now() + 86400000).toISOString(), used_at: new Date().toISOString() }],
    });
    const res = await request(app).get(`/v1/portal/auth/verify-email?token=${raw}`);
    expect(res.status).toBe(302);
    expect(res.headers['location']).toMatch(/error=invalid/);
  });

  test('302 to /verify-email?error=expired for expired unused token', async () => {
    const { raw } = generateVerificationToken();
    // used_at is null (unused) but past expires_at
    mockQuery.mockResolvedValueOnce({
      rows: [{ token_id: 't1', user_id: 'u1', expires_at: new Date(Date.now() - 1000).toISOString(), used_at: null }],
    });
    const res = await request(app).get(`/v1/portal/auth/verify-email?token=${raw}`);
    expect(res.status).toBe(302);
    expect(res.headers['location']).toMatch(/error=expired/);
  });

  test('302 to /login?verified=true on valid unused non-expired token', async () => {
    const { raw } = generateVerificationToken();
    mockQuery.mockResolvedValueOnce({
      rows: [{ token_id: 't1', user_id: 'u1', expires_at: new Date(Date.now() + 86400000).toISOString(), used_at: null }],
    });
    const mockClient = {
      query: jest.fn()
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce(undefined) // UPDATE tokens
        .mockResolvedValueOnce(undefined) // UPDATE users
        .mockResolvedValueOnce(undefined), // COMMIT
      release: jest.fn(),
    };
    mockConnect.mockResolvedValueOnce(mockClient);
    const res = await request(app).get(`/v1/portal/auth/verify-email?token=${raw}`);
    expect(res.status).toBe(302);
    expect(res.headers['location']).toMatch(/\/login\?verified=true/);
  });
});

// ── Resend Verification ────────────────────────────────────────────────────────
describe('POST /v1/portal/auth/resend-verification', () => {
  test('204 always — even for unknown email (anti-enumeration)', async () => {
    // Rate check returns 0; user lookup returns no rows
    mockQuery.mockResolvedValueOnce({ rows: [{ cnt: '0' }] }); // rate check
    mockQuery.mockResolvedValueOnce({ rows: [] }); // no user found
    const res = await request(app).post('/v1/portal/auth/resend-verification')
      .send({ email: 'nobody@company.com' });
    expect(res.status).toBe(204);
    expect(mockSendEmail).not.toHaveBeenCalled();
  });

  test('204 always — rate limited (3+ sends/hr), no email sent', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ cnt: '3' }] }); // rate limit hit
    const res = await request(app).post('/v1/portal/auth/resend-verification')
      .send({ email: 'alice@company.com' });
    expect(res.status).toBe(204);
    expect(mockSendEmail).not.toHaveBeenCalled();
  });

  test('204 and sends email for valid unverified user under rate limit', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ cnt: '0' }] }); // rate check
    mockQuery.mockResolvedValueOnce({ rows: [{ user_id: 'u1', full_name: 'Alice' }] }); // user found
    const mockClient = {
      query: jest.fn()
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce(undefined) // invalidate old tokens
        .mockResolvedValueOnce(undefined) // insert new token
        .mockResolvedValueOnce(undefined) // log resend
        .mockResolvedValueOnce(undefined), // COMMIT
      release: jest.fn(),
    };
    mockConnect.mockResolvedValueOnce(mockClient);
    const res = await request(app).post('/v1/portal/auth/resend-verification')
      .send({ email: 'alice@company.com' });
    expect(res.status).toBe(204);
    expect(mockSendEmail).toHaveBeenCalledWith(expect.objectContaining({ to: 'alice@company.com' }));
  });

  test('204 with no body — safe no-op', async () => {
    const res = await request(app).post('/v1/portal/auth/resend-verification').send({});
    expect(res.status).toBe(204);
    expect(mockSendEmail).not.toHaveBeenCalled();
  });
});
