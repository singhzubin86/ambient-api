/**
 * Campaign CRUD routes
 *  POST   /v1/campaigns          — create campaign
 *  GET    /v1/campaigns          — list campaigns for advertiser
 *  GET    /v1/campaigns/:id      — get campaign
 *  PATCH  /v1/campaigns/:id      — update campaign (status, creative, targeting, budget)
 *
 * Warden/Ledger requirements:
 *  - advertiser_category is required, non-nullable
 *  - BLOCKED categories: hard 422 reject at API layer
 *  - CONDITIONAL categories: status auto-set to 'pending_review'
 *  - legal_services: requires advertiser_self_certified_compliance=true
 *  - rejection_reason populated on status='rejected' via PATCH
 *  - disclosure_label + disclosure_placement non-nullable on creative
 *
 * State machine:
 *  draft → pending_review (auto for conditional categories)
 *  pending_review → active | rejected  (manual, via PATCH, admin only)
 *  active → paused | ended  (advertiser or admin)
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getPool } from '../../db/pool';
import { advertiserJwtAuth, requireRole } from '../../middleware/auth';
import { stemKeywords } from '../../services/stemmer';
import { config } from '../../lib/config';
import { logger } from '../../lib/logger';
import { CreateCampaignRequest, JwtPayload } from '../../types';

export const campaignsRouter = Router();

const BLOCKED = new Set(config.advertiserCategories.blocked as readonly string[]);
const CONDITIONAL = new Set(config.advertiserCategories.conditional as readonly string[]);
// Legal services requires self-certification attestation
const SELF_CERT_REQUIRED = new Set(['legal_services']);

// legal_services is also a conditional category (requires review)
const LEGAL_SERVICES_CONDITIONAL = new Set(['legal_services']);

// POST /v1/campaigns
campaignsRouter.post('/', advertiserJwtAuth, requireRole('advertiser', 'admin'), async (req: Request, res: Response): Promise<void> => {
  const jwt = (req as any).jwtPayload as JwtPayload;
  const body = req.body as CreateCampaignRequest & { advertiser_self_certified_compliance?: boolean };

  // ── Validate required fields ──────────────────────────────────────────────
  const missing = ['name', 'advertiser_category', 'creative', 'targeting', 'budget_total_cents', 'budget_daily_cents', 'flight_start', 'flight_end']
    .filter((f) => !(f in body));
  if (missing.length) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: `Missing required fields: ${missing.join(', ')}` });
    return;
  }
  const creative = body.creative;
  if (!creative.disclosure_label || !creative.disclosure_placement) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'creative.disclosure_label and disclosure_placement are required (Warden requirement)' });
    return;
  }
  if (!['Ad', 'Sponsored'].includes(creative.disclosure_label)) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'disclosure_label must be "Ad" or "Sponsored"' });
    return;
  }
  if (!['prepend', 'surround'].includes(creative.disclosure_placement)) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'disclosure_placement must be "prepend" or "surround"' });
    return;
  }

  // ── Warden: blocked category hard-reject ─────────────────────────────────
  if (BLOCKED.has(body.advertiser_category)) {
    logger.warn({ msg: 'BLOCKED_CATEGORY_REJECTED', category: body.advertiser_category, advertiserId: jwt.advertiser_id });
    res.status(422).json({
      error: 'BLOCKED_ADVERTISER_CATEGORY',
      message: `Campaigns in category '${body.advertiser_category}' are not accepted on the Ambient platform.`,
      category: body.advertiser_category,
    });
    return;
  }

  // ── Warden: legal_services self-certification ─────────────────────────────
  if (SELF_CERT_REQUIRED.has(body.advertiser_category) && body.advertiser_self_certified_compliance !== true) {
    res.status(400).json({
      error: 'SELF_CERTIFICATION_REQUIRED',
      message: `Category 'legal_services' requires advertiser_self_certified_compliance: true. Advertiser must attest compliance before campaign creation.`,
    });
    return;
  }

  // ── Determine initial status ──────────────────────────────────────────────
  const isConditional = CONDITIONAL.has(body.advertiser_category) || LEGAL_SERVICES_CONDITIONAL.has(body.advertiser_category);
  const initialStatus = isConditional ? 'pending_review' : 'draft';

  // ── Pre-compute stemmed keywords (Signal Decision 2) ──────────────────────
  const targetingKeywords = body.targeting.keywords ?? [];
  const stemmed = stemKeywords(targetingKeywords);

  const pool = getPool();
  const campaignId = uuidv4();
  const advertiserId = jwt.advertiser_id!;

  await pool.query(
    `INSERT INTO campaigns (
      campaign_id, advertiser_id, name, advertiser_category, status,
      headline, body, cta_text, destination_url, disclosure_label, disclosure_placement,
      targeting_keywords, targeting_keywords_stemmed, targeting_surfaces,
      budget_total_cents, budget_daily_cents, cpm_floor_cents,
      flight_start, flight_end
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
    [
      campaignId, advertiserId, body.name, body.advertiser_category, initialStatus,
      creative.headline, creative.body, creative.cta_text, creative.destination_url,
      creative.disclosure_label, creative.disclosure_placement,
      targetingKeywords, stemmed, body.targeting.surfaces ?? [],
      body.budget_total_cents, body.budget_daily_cents, (body as any).cpm_floor_cents ?? 0,
      body.flight_start, body.flight_end,
    ],
  );

  // ── Auto-enqueue for review if conditional ────────────────────────────────
  if (isConditional) {
    await pool.query(
      `INSERT INTO campaign_review_queue (campaign_id, reason) VALUES ($1, $2)`,
      [campaignId, `Conditional advertiser category: ${body.advertiser_category}`],
    );
    logger.info({ msg: 'campaign_pending_review', campaignId, category: body.advertiser_category });
  }

  logger.info({ msg: 'campaign_created', campaignId, status: initialStatus });
  res.status(201).json({ campaign_id: campaignId, status: initialStatus });
});

// GET /v1/campaigns
campaignsRouter.get('/', advertiserJwtAuth, async (req: Request, res: Response): Promise<void> => {
  const jwt = (req as any).jwtPayload as JwtPayload;
  const pool = getPool();
  const { rows } = await pool.query(
    `SELECT campaign_id, name, advertiser_category, status, headline, cta_text,
            budget_total_cents, budget_daily_cents, cpm_floor_cents,
            flight_start, flight_end, created_at, updated_at
     FROM campaigns WHERE advertiser_id = $1 ORDER BY created_at DESC`,
    [jwt.advertiser_id],
  );
  res.json(rows);
});

// GET /v1/campaigns/:id
campaignsRouter.get('/:id', advertiserJwtAuth, async (req: Request, res: Response): Promise<void> => {
  const jwt = (req as any).jwtPayload as JwtPayload;
  const pool = getPool();
  const { rows } = await pool.query(
    'SELECT * FROM campaigns WHERE campaign_id = $1 AND advertiser_id = $2',
    [req.params['id'], jwt.advertiser_id],
  );
  if (!rows[0]) { res.status(404).json({ error: 'NOT_FOUND', message: 'Campaign not found' }); return; }
  res.json(rows[0]);
});

// PATCH /v1/campaigns/:id
campaignsRouter.patch('/:id', advertiserJwtAuth, async (req: Request, res: Response): Promise<void> => {
  const jwt = (req as any).jwtPayload as JwtPayload;
  const pool = getPool();
  const campaignId = req.params['id']!;

  // Fetch current campaign
  const { rows } = await pool.query(
    'SELECT * FROM campaigns WHERE campaign_id = $1 AND advertiser_id = $2',
    [campaignId, jwt.advertiser_id],
  );
  const campaign = rows[0];
  if (!campaign) { res.status(404).json({ error: 'NOT_FOUND', message: 'Campaign not found' }); return; }

  const updates: Record<string, unknown> = {};
  const params: unknown[] = [];

  // Status transitions
  if (req.body.status !== undefined) {
    const newStatus: string = req.body.status;
    const isAdmin = jwt.role === 'admin';

    // State machine enforcement
    const allowed = getAllowedTransitions(campaign.status, isAdmin);
    if (!allowed.includes(newStatus)) {
      res.status(422).json({
        error: 'INVALID_STATUS_TRANSITION',
        message: `Cannot transition campaign from '${campaign.status}' to '${newStatus}'`,
      });
      return;
    }

    updates['status'] = newStatus;

    // rejection_reason required on reject
    if (newStatus === 'rejected') {
      if (!req.body.rejection_reason) {
        res.status(400).json({ error: 'INVALID_REQUEST', message: 'rejection_reason is required when rejecting a campaign' });
        return;
      }
      updates['rejection_reason'] = req.body.rejection_reason;
      // Resolve review queue entry
      await pool.query(
        `UPDATE campaign_review_queue SET status='rejected', reviewer_notes=$1, resolved_at=NOW() WHERE campaign_id=$2 AND status='pending'`,
        [req.body.rejection_reason, campaignId],
      );
    }
    if (newStatus === 'active' && campaign.status === 'pending_review') {
      await pool.query(
        `UPDATE campaign_review_queue SET status='approved', resolved_at=NOW() WHERE campaign_id=$1 AND status='pending'`,
        [campaignId],
      );
    }
  }

  // Optional field updates
  if (req.body.name) updates['name'] = req.body.name;
  if (req.body.budget_total_cents) updates['budget_total_cents'] = req.body.budget_total_cents;
  if (req.body.budget_daily_cents) updates['budget_daily_cents'] = req.body.budget_daily_cents;
  if (req.body.flight_start) updates['flight_start'] = req.body.flight_start;
  if (req.body.flight_end) updates['flight_end'] = req.body.flight_end;

  // Creative updates (preserve disclosure fields)
  if (req.body.creative) {
    const c = req.body.creative;
    if (c.headline) updates['headline'] = c.headline;
    if (c.body) updates['body'] = c.body;
    if (c.cta_text) updates['cta_text'] = c.cta_text;
    if (c.destination_url) updates['destination_url'] = c.destination_url;
    if (c.disclosure_label) updates['disclosure_label'] = c.disclosure_label;
    if (c.disclosure_placement) updates['disclosure_placement'] = c.disclosure_placement;
  }

  // Targeting update with re-stemming
  if (req.body.targeting) {
    const kw = req.body.targeting.keywords ?? campaign.targeting_keywords;
    updates['targeting_keywords'] = kw;
    updates['targeting_keywords_stemmed'] = stemKeywords(kw);
    if (req.body.targeting.surfaces) updates['targeting_surfaces'] = req.body.targeting.surfaces;
  }

  if (Object.keys(updates).length === 0) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'No updatable fields provided' });
    return;
  }

  const setClauses = Object.keys(updates).map((k, i) => `${k} = $${i + 2}`).join(', ');
  const values = Object.values(updates);
  await pool.query(
    `UPDATE campaigns SET ${setClauses}, updated_at = NOW() WHERE campaign_id = $1`,
    [campaignId, ...values],
  );

  logger.info({ msg: 'campaign_updated', campaignId, updates: Object.keys(updates) });
  res.json({ campaign_id: campaignId, updated: Object.keys(updates) });
});

function getAllowedTransitions(currentStatus: string, isAdmin: boolean): string[] {
  switch (currentStatus) {
    case 'draft':        return ['active', 'pending_review'];
    case 'pending_review': return isAdmin ? ['active', 'rejected'] : [];
    case 'active':       return ['paused', 'ended'];
    case 'paused':       return ['active', 'ended'];
    case 'rejected':     return [];
    case 'ended':        return [];
    default:             return [];
  }
}
