/**
 * Integration tests — Publisher reporting (SPEC-6)
 *
 * GET /v1/portal/publishers/me/stats
 * GET /v1/portal/publishers/me/integration-status
 */
import request from 'supertest';
import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { createApp } from '../../src/index';
import { LogRecord } from '../../src/services/log-store';

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
jest.mock('../../src/db/pool', () => ({
  getPool: () => ({ query: mockQuery, connect: jest.fn() }),
  closePool: jest.fn(),
}));

let app: express.Application;
let tmpWalDir: string;

beforeAll(async () => {
  // Create a temp WAL dir for log-store reads in reporting
  tmpWalDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ambient-wal-'));
  process.env['WAL_DIR'] = tmpWalDir;
  app = await createApp();
});

afterAll(() => {
  // Cleanup temp dir
  try { fs.rmSync(tmpWalDir, { recursive: true }); } catch {}
});

beforeEach(() => {
  jest.clearAllMocks();
  mockRedisGet.mockResolvedValue(null);
  // Clear WAL file between tests
  const walFile = path.join(tmpWalDir, 'pending.wal');
  if (fs.existsSync(walFile)) fs.unlinkSync(walFile);
});

function makePublisherJwt(userId = 'u1'): string {
  const secret = process.env['JWT_SECRET'] ?? 'dev-jwt-secret-change-in-production-32c';
  return jwt.sign(
    { sub: userId, email: 'alice@company.com', role: 'publisher', jti: crypto.randomBytes(8).toString('hex') },
    secret,
    { expiresIn: 86400 },
  );
}

/** Write fake log records to WAL file */
function writeWalRecords(records: Partial<LogRecord>[]): void {
  const walFile = path.join(tmpWalDir, 'pending.wal');
  const lines = records.map((r) => JSON.stringify({
    v: 1, seq: 1, prev_hash: 'genesis', record_hmac: 'test',
    timestamp_utc_ms: Date.now(),
    publisher_id: 'pub1',
    ...r,
  }));
  fs.writeFileSync(walFile, lines.join('\n') + '\n');
}

// ── Stats ──────────────────────────────────────────────────────────────────────
describe('GET /v1/portal/publishers/me/stats', () => {
  test('401 without session', async () => {
    const res = await request(app).get('/v1/portal/publishers/me/stats');
    expect(res.status).toBe(401);
  });

  test('404 when no publisher record', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await request(app).get('/v1/portal/publishers/me/stats')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(404);
  });

  test('422 for invalid date range (start > end)', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{ publisher_id: 'pub1', cpm_usd: '5.0000' }] });
    const res = await request(app).get('/v1/portal/publishers/me/stats?start_date=2026-08-10&end_date=2026-08-01')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(422);
  });

  test('200 returns summary with zero stats when WAL is empty', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{ publisher_id: 'pub1', cpm_usd: '5.0000' }] });
    const res = await request(app).get('/v1/portal/publishers/me/stats')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.summary.total_impressions).toBe(0);
    expect(res.body.summary.total_clicks).toBe(0);
    expect(res.body.summary.overall_ctr).toBe(0);
    expect(res.body.rows).toHaveLength(0);
  });

  test('200 returns correct impression count from WAL', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{ publisher_id: 'pub1', cpm_usd: '5.0000' }] });

    const now = Date.now();
    writeWalRecords([
      { event_type: 'impression', publisher_id: 'pub1', timestamp_utc_ms: now },
      { event_type: 'impression', publisher_id: 'pub1', timestamp_utc_ms: now - 1000 },
      { event_type: 'click', publisher_id: 'pub1', timestamp_utc_ms: now },
      // Different publisher — must NOT be counted
      { event_type: 'impression', publisher_id: 'pub_other', timestamp_utc_ms: now },
    ]);

    const today = new Date(now).toISOString().slice(0, 10);
    const res = await request(app)
      .get(`/v1/portal/publishers/me/stats?start_date=${today}&end_date=${today}`)
      .set('Cookie', `__Host-amb-portal=${token}`);

    expect(res.status).toBe(200);
    expect(res.body.summary.total_impressions).toBe(2);
    expect(res.body.summary.total_clicks).toBe(1);
    expect(res.body.summary.overall_ctr).toBeCloseTo(0.5, 4);
    // spend = 2 impressions * 5.00 CPM / 1000
    expect(res.body.summary.total_spend_usd).toBeCloseTo(0.01, 4);
  });
});

// ── Integration Status ─────────────────────────────────────────────────────────
describe('GET /v1/portal/publishers/me/integration-status', () => {
  test('401 without session', async () => {
    const res = await request(app).get('/v1/portal/publishers/me/integration-status');
    expect(res.status).toBe(401);
  });

  test('404 when no publisher record', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await request(app).get('/v1/portal/publishers/me/integration-status')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(404);
  });

  test('not_integrated when WAL has no impressions for publisher', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{ publisher_id: 'pub1' }] });
    // WAL is empty (no file written)
    const res = await request(app).get('/v1/portal/publishers/me/integration-status')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.integration_status).toBe('not_integrated');
  });

  test('live when impression exists within last 48h', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{ publisher_id: 'pub1' }] });
    writeWalRecords([{
      event_type: 'impression',
      publisher_id: 'pub1',
      timestamp_utc_ms: Date.now() - 1000, // 1 second ago
    }]);
    const res = await request(app).get('/v1/portal/publishers/me/integration-status')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.integration_status).toBe('live');
    expect(res.body.checked_at).toBeDefined();
  });

  test('no_signal when all impressions are older than 48h', async () => {
    const token = makePublisherJwt();
    mockQuery.mockResolvedValueOnce({ rows: [{ publisher_id: 'pub1' }] });
    writeWalRecords([{
      event_type: 'impression',
      publisher_id: 'pub1',
      timestamp_utc_ms: Date.now() - 49 * 60 * 60 * 1000, // 49 hours ago
    }]);
    const res = await request(app).get('/v1/portal/publishers/me/integration-status')
      .set('Cookie', `__Host-amb-portal=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.integration_status).toBe('no_signal');
  });
});
