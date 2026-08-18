/**
 * Publisher self-service routes (portal-authenticated)
 * Spec: AMBIENT_PROTOTYPE_SPECS.md R3 SPEC-3
 *
 * POST   /v1/publishers             — onboard publisher (links portal_user → publisher record)
 * GET    /v1/publishers/me          — get own publisher record + masked API key
 * POST   /v1/publishers/me/regenerate-key — rotate API key (returns new key once)
 */
import { Router, Request, Response } from 'express';
import { getPool } from '../../db/pool';
import { logger } from '../../lib/logger';
import { portalAuth, requirePortalRole } from '../../middleware/portal-auth-middleware';
import {
  generatePublisherApiKey,
  maskApiKey,
  PortalJwtPayload,
} from '../../lib/portal-auth';

export const portalPublishersRouter = Router();

// All routes require an authenticated portal session with publisher or both role
portalPublishersRouter.use(portalAuth);
portalPublishersRouter.use(requirePortalRole('publisher', 'both'));

// ── POST /v1/publishers — self-service onboarding ─────────────────────────────
// Creates (or returns existing) publisher record for the authenticated portal user.
// Idempotent: a second call with the same user returns 409 CONFLICT with publisher_id.
portalPublishersRouter.post('/', async (req: Request, res: Response): Promise<void> => {
  const jwtUser: PortalJwtPayload = (req as any).portalUser;
  const {
    app_name,
    app_url,
    app_category,
    mau_range,
    integration_type,
  } = req.body ?? {};

  // Validate required fields
  const errors: Record<string, string> = {};
  if (!app_name || typeof app_name !== 'string') errors['app_name'] = 'required';
  if (!app_url || typeof app_url !== 'string') errors['app_url'] = 'required';
  if (!app_category) errors['app_category'] = 'required';
  if (!mau_range) errors['mau_range'] = 'required';
  if (!integration_type) errors['integration_type'] = 'required';

  if (Object.keys(errors).length > 0) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors });
    return;
  }

  const validCategories = ['custom_gpt', 'standalone_chatbot', 'voice_ai', 'rag_app', 'other'];
  if (!validCategories.includes(app_category as string)) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { app_category: `must be one of: ${validCategories.join(', ')}` } });
    return;
  }
  const validMau = ['lt1k', '1k_10k', '10k_100k', '100k_plus'];
  if (!validMau.includes(mau_range as string)) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { mau_range: `must be one of: ${validMau.join(', ')}` } });
    return;
  }
  const validIntegration = ['standalone_web_chatbot', 'other'];
  if (!validIntegration.includes(integration_type as string)) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { integration_type: `must be one of: ${validIntegration.join(', ')}` } });
    return;
  }

  const pool = getPool();

  // Check idempotency — if this user already has a publisher record, reject
  const existing = await pool.query(
    `SELECT publisher_id FROM publishers WHERE portal_user_id = $1`,
    [jwtUser.sub],
  );
  if (existing.rows.length > 0) {
    res.status(409).json({
      error: 'CONFLICT',
      message: 'A publisher record already exists for this account',
      publisher_id: existing.rows[0].publisher_id,
    });
    return;
  }

  // Get portal user details for the publisher record
  const { rows: userRows } = await pool.query(
    `SELECT email, full_name, company_name FROM portal_users WHERE user_id = $1`,
    [jwtUser.sub],
  );
  const portalUser = userRows[0];
  if (!portalUser) {
    res.status(401).json({ error: 'UNAUTHENTICATED', message: 'User not found' });
    return;
  }

  // Generate API key — HMAC-SHA256, never bcrypt (Blueprint decision)
  const { apiKey, keyHash } = generatePublisherApiKey(false);
  const keyPrefix = apiKey.slice(0, 9); // "amb_live_" = 9 chars

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO publishers
         (name, contact_email, api_key_hash, api_key_prefix, status,
          portal_user_id, app_name, app_url, app_category, mau_range, integration_type)
       VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10)
       RETURNING publisher_id, name, contact_email, api_key_prefix, status, created_at,
                 app_name, app_url, app_category, mau_range, integration_type, cpm_usd`,
      [
        (app_name as string).trim(),
        portalUser.email,
        keyHash,
        keyPrefix,
        jwtUser.sub,
        (app_name as string).trim(),
        (app_url as string).trim(),
        app_category,
        mau_range,
        integration_type,
      ],
    );
    await client.query('COMMIT');

    const pub = result.rows[0];
    logger.info({ msg: 'publisher.created', publisherId: pub.publisher_id, userId: jwtUser.sub });

    // Return full API key — shown ONCE only
    res.status(201).json({
      publisher_id: pub.publisher_id,
      name: pub.name,
      contact_email: pub.contact_email,
      api_key: apiKey,           // full key — shown once
      api_key_prefix: pub.api_key_prefix,
      status: pub.status,
      app_name: pub.app_name,
      app_url: pub.app_url,
      app_category: pub.app_category,
      mau_range: pub.mau_range,
      integration_type: pub.integration_type,
      cpm_usd: parseFloat(pub.cpm_usd),
      created_at: pub.created_at,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error({ msg: 'publisher.create failed', err: (err as Error).message });
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Publisher creation failed' });
  } finally {
    client.release();
  }
});

// ── GET /v1/publishers/me — get own publisher record ──────────────────────────
portalPublishersRouter.get('/me', async (req: Request, res: Response): Promise<void> => {
  const jwtUser: PortalJwtPayload = (req as any).portalUser;
  const pool = getPool();

  const { rows } = await pool.query(
    `SELECT publisher_id, name, contact_email, api_key_prefix, status, created_at,
            app_name, app_url, app_category, mau_range, integration_type, cpm_usd
     FROM publishers WHERE portal_user_id = $1`,
    [jwtUser.sub],
  );
  const pub = rows[0];
  if (!pub) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'No publisher record found — complete onboarding first' });
    return;
  }

  res.json({
    publisher_id: pub.publisher_id,
    name: pub.name,
    contact_email: pub.contact_email,
    api_key_masked: maskApiKey(`amb_live_xxxx${pub.api_key_prefix.slice(-4)}`),
    api_key_prefix: pub.api_key_prefix,
    status: pub.status,
    app_name: pub.app_name,
    app_url: pub.app_url,
    app_category: pub.app_category,
    mau_range: pub.mau_range,
    integration_type: pub.integration_type,
    cpm_usd: parseFloat(pub.cpm_usd),
    created_at: pub.created_at,
  });
});

// ── POST /v1/publishers/me/regenerate-key — rotate API key ───────────────────
// Returns the new key exactly once. Old key is invalidated immediately.
portalPublishersRouter.post('/me/regenerate-key', async (req: Request, res: Response): Promise<void> => {
  const jwtUser: PortalJwtPayload = (req as any).portalUser;
  const pool = getPool();

  const { rows } = await pool.query(
    `SELECT publisher_id FROM publishers WHERE portal_user_id = $1 AND status = 'active'`,
    [jwtUser.sub],
  );
  const pub = rows[0];
  if (!pub) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'No active publisher record found' });
    return;
  }

  const { apiKey, keyHash } = generatePublisherApiKey(false);
  const keyPrefix = apiKey.slice(0, 9);

  await pool.query(
    `UPDATE publishers SET api_key_hash = $1, api_key_prefix = $2 WHERE publisher_id = $3`,
    [keyHash, keyPrefix, pub.publisher_id],
  );

  logger.info({ msg: 'publisher.key_rotated', publisherId: pub.publisher_id, userId: jwtUser.sub });

  res.json({
    publisher_id: pub.publisher_id,
    api_key: apiKey,           // full new key — shown once
    api_key_prefix: keyPrefix,
  });
});
