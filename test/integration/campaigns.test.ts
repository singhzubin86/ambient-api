/**
 * Integration tests — Campaign CRUD
 * POST /v1/campaigns, GET, PATCH
 * Covers: blocked categories, conditional categories, pending_review state machine,
 *         disclosure fields, self-certification, rejection_reason
 */
import request from 'supertest';
import express from 'express';
import { createApp } from '../../src/index';

jest.mock('../../src/db/pool', () => {
  const mockQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  return {
    getPool: () => ({ query: mockQuery }),
    closePool: jest.fn(),
    __mockQuery: mockQuery,
  };
});
jest.mock('../../src/db/redis', () => ({ getRedis: () => ({ get: jest.fn().mockResolvedValue(null), set: jest.fn().mockResolvedValue('OK'), pipeline: () => ({ incr: jest.fn(), expire: jest.fn(), exec: jest.fn().mockResolvedValue([]) }), quit: jest.fn() }), closeRedis: jest.fn() }));
jest.mock('../../src/services/log-store', () => ({ initLogStore: jest.fn().mockResolvedValue(undefined), shutdownLogStore: jest.fn().mockResolvedValue(undefined), appendRecord: jest.fn() }));
jest.mock('../../src/services/campaign-cache', () => ({ loadCampaigns: jest.fn().mockResolvedValue(undefined), startCampaignCacheRefresh: jest.fn(), stopCampaignCacheRefresh: jest.fn(), getCampaignArray: jest.fn().mockReturnValue([]) }));
jest.mock('../../src/services/anomaly-monitor', () => ({ startAnomalyMonitor: jest.fn(), stopAnomalyMonitor: jest.fn() }));
jest.mock('../../src/middleware/auth', () => ({
  publisherApiKeyAuth: (_r: any, _s: any, n: any) => { _r.publisherId = 'pub_1'; n(); },
  advertiserJwtAuth: (_r: any, _s: any, n: any) => { _r.jwtPayload = { sub: 'u1', role: 'admin', advertiser_id: 'adv_1' }; n(); },
  requireRole: () => (_r: any, _s: any, n: any) => n(),
}));

import * as dbPool from '../../src/db/pool';
const getMockQuery = () => (dbPool as any).__mockQuery as jest.Mock;

const validBody = {
  name: 'My Campaign',
  advertiser_category: 'general',
  creative: {
    headline: 'Buy Now',
    body: 'Great deal.',
    cta_text: 'Shop',
    destination_url: 'https://example.com',
    disclosure_label: 'Ad',
    disclosure_placement: 'prepend',
  },
  targeting: { keywords: ['travel', 'hotel'] },
  budget_total_cents: 100_000,
  budget_daily_cents: 10_000,
  flight_start: '2026-08-01',
  flight_end: '2026-12-31',
};

let app: express.Application;
beforeAll(async () => { app = await createApp(); });

describe('POST /v1/campaigns', () => {
  beforeEach(() => { getMockQuery().mockResolvedValue({ rows: [], rowCount: 0 }); });

  test('creates campaign and returns 201 for general category', async () => {
    const res = await request(app).post('/v1/campaigns').send(validBody);
    expect(res.status).toBe(201);
    expect(res.body.campaign_id).toBeDefined();
    expect(res.body.status).toBe('draft');
  });

  // Warden — blocked categories
  const BLOCKED = ['pharma_rx', 'investment_securities', 'gambling', 'cannabis', 'political', 'adult'];
  for (const cat of BLOCKED) {
    test(`hard-rejects blocked category: ${cat} (Warden requirement)`, async () => {
      const res = await request(app).post('/v1/campaigns')
        .send({ ...validBody, advertiser_category: cat });
      expect(res.status).toBe(422);
      expect(res.body.error).toBe('BLOCKED_ADVERTISER_CATEGORY');
    });
  }

  // Warden — conditional categories → pending_review
  const CONDITIONAL = ['alcohol', 'firearms', 'financial_services', 'healthcare_general'];
  for (const cat of CONDITIONAL) {
    test(`sets status=pending_review for conditional category: ${cat}`, async () => {
      const res = await request(app).post('/v1/campaigns')
        .send({ ...validBody, advertiser_category: cat });
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('pending_review');
    });
  }

  test('rejects legal_services without self-certification attestation', async () => {
    const res = await request(app).post('/v1/campaigns')
      .send({ ...validBody, advertiser_category: 'legal_services' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('SELF_CERTIFICATION_REQUIRED');
  });

  test('accepts legal_services with advertiser_self_certified_compliance=true', async () => {
    const res = await request(app).post('/v1/campaigns')
      .send({ ...validBody, advertiser_category: 'legal_services', advertiser_self_certified_compliance: true });
    expect(res.status).toBe(201);
    expect(res.body.status).toBe('pending_review'); // legal_services is conditional
  });

  test('rejects missing disclosure_label (Warden requirement)', async () => {
    const { disclosure_label, ...creativeNoLabel } = validBody.creative;
    const res = await request(app).post('/v1/campaigns')
      .send({ ...validBody, creative: creativeNoLabel });
    expect(res.status).toBe(400);
  });

  test('rejects invalid disclosure_label value', async () => {
    const res = await request(app).post('/v1/campaigns')
      .send({ ...validBody, creative: { ...validBody.creative, disclosure_label: 'Promo' } });
    expect(res.status).toBe(400);
  });

  test('rejects missing advertiser_category', async () => {
    const { advertiser_category, ...body } = validBody;
    const res = await request(app).post('/v1/campaigns').send(body);
    expect(res.status).toBe(400);
  });
});

describe('PATCH /v1/campaigns/:id — state machine', () => {
  function mockExistingCampaign(status: string) {
    const mockFn = getMockQuery();
    mockFn.mockReset();
    mockFn.mockResolvedValueOnce({ rows: [{ campaign_id: 'camp_1', advertiser_id: 'adv_1', status, targeting_keywords: [] }], rowCount: 1 });
    mockFn.mockResolvedValue({ rows: [], rowCount: 1 });
  }

  test('rejects pending_review → rejected without rejection_reason', async () => {
    mockExistingCampaign('pending_review');
    const res = await request(app).patch('/v1/campaigns/camp_1').send({ status: 'rejected' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INVALID_REQUEST');
  });

  test('allows pending_review → rejected with rejection_reason (admin)', async () => {
    mockExistingCampaign('pending_review');
    const res = await request(app).patch('/v1/campaigns/camp_1')
      .send({ status: 'rejected', rejection_reason: 'Category documentation incomplete' });
    expect(res.status).toBe(200);
  });

  test('allows pending_review → active (admin approval)', async () => {
    mockExistingCampaign('pending_review');
    const res = await request(app).patch('/v1/campaigns/camp_1').send({ status: 'active' });
    expect(res.status).toBe(200);
  });

  test('blocks invalid transition: rejected → active', async () => {
    mockExistingCampaign('rejected');
    const res = await request(app).patch('/v1/campaigns/camp_1').send({ status: 'active' });
    expect(res.status).toBe(422);
    expect(res.body.error).toBe('INVALID_STATUS_TRANSITION');
  });

  test('blocks invalid transition: ended → active', async () => {
    mockExistingCampaign('ended');
    const res = await request(app).patch('/v1/campaigns/camp_1').send({ status: 'active' });
    expect(res.status).toBe(422);
  });
});
