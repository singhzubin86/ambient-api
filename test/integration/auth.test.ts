/**
 * Integration tests — Auth
 * POST /v1/auth/login, POST /v1/auth/refresh
 */
import request from 'supertest';
import express from 'express';
import bcrypt from 'bcryptjs';
import { createApp } from '../../src/index';

jest.mock('../../src/services/log-store', () => ({ initLogStore: jest.fn().mockResolvedValue(undefined), shutdownLogStore: jest.fn().mockResolvedValue(undefined), appendRecord: jest.fn() }));
jest.mock('../../src/services/campaign-cache', () => ({ loadCampaigns: jest.fn().mockResolvedValue(undefined), startCampaignCacheRefresh: jest.fn(), stopCampaignCacheRefresh: jest.fn(), getCampaignArray: jest.fn().mockReturnValue([]) }));
jest.mock('../../src/services/anomaly-monitor', () => ({ startAnomalyMonitor: jest.fn(), stopAnomalyMonitor: jest.fn() }));
jest.mock('../../src/db/redis', () => ({ getRedis: () => ({ get: jest.fn(), set: jest.fn(), quit: jest.fn(), pipeline: () => ({ incr: jest.fn(), expire: jest.fn(), exec: jest.fn().mockResolvedValue([]) }) }), closeRedis: jest.fn() }));
jest.mock('../../src/db/pool', () => {
  const mockQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  return { getPool: () => ({ query: mockQuery }), closePool: jest.fn(), __mockQuery: mockQuery };
});

import * as dbPool from '../../src/db/pool';
const getDbQuery = () => (dbPool as any).__mockQuery as jest.Mock;

let app: express.Application;
beforeAll(async () => { app = await createApp(); });

describe('POST /v1/auth/login', () => {
  test('returns 400 when email or password missing', async () => {
    const res = await request(app).post('/v1/auth/login').send({ email: 'a@b.com' });
    expect(res.status).toBe(400);
  });

  test('returns 401 for unknown email', async () => {
    getDbQuery().mockResolvedValueOnce({ rows: [] });
    const res = await request(app).post('/v1/auth/login')
      .send({ email: 'nobody@example.com', password: 'secret' });
    expect(res.status).toBe(401);
  });

  test('returns 401 for wrong password', async () => {
    const hash = await bcrypt.hash('correct', 10);
    getDbQuery().mockResolvedValueOnce({
      rows: [{ user_id: 'u1', advertiser_id: 'adv_1', password_hash: hash, role: 'advertiser' }],
    });
    const res = await request(app).post('/v1/auth/login')
      .send({ email: 'user@example.com', password: 'wrong' });
    expect(res.status).toBe(401);
  });

  test('returns JWT token on valid credentials', async () => {
    const hash = await bcrypt.hash('secret123', 10);
    getDbQuery().mockResolvedValueOnce({
      rows: [{ user_id: 'u1', advertiser_id: 'adv_1', password_hash: hash, role: 'advertiser' }],
    });
    const res = await request(app).post('/v1/auth/login')
      .send({ email: 'user@example.com', password: 'secret123' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.role).toBe('advertiser');
    expect(typeof res.body.expires_in).toBe('number');
  });
});
