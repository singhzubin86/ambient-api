/**
 * Publisher routes (Campaign & Key Management)
 *  POST   /v1/publishers             — onboard publisher, provision API key
 *  GET    /v1/publishers/:id         — get publisher (admin only)
 *  POST   /v1/publishers/:id/rotate-key — rotate API key
 */
import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getPool } from '../../db/pool';
import { config } from '../../lib/config';
import { advertiserJwtAuth, requireRole } from '../../middleware/auth';
import { logger } from '../../lib/logger';

export const publishersRouter = Router();

// POST /v1/publishers
publishersRouter.post('/', advertiserJwtAuth, requireRole('admin'), async (req: Request, res: Response): Promise<void> => {
  const { name, contact_email } = req.body;
  if (!name || !contact_email) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'name and contact_email required' });
    return;
  }

  const { apiKey, prefix, hash } = await generateApiKey();
  const publisherId = uuidv4();
  const pool = getPool();

  await pool.query(
    `INSERT INTO publishers (publisher_id, name, contact_email, api_key_hash, api_key_prefix, status)
     VALUES ($1, $2, $3, $4, $5, 'active')`,
    [publisherId, name, contact_email, hash, prefix],
  );
  await pool.query(
    `INSERT INTO api_key_events (publisher_id, event_type) VALUES ($1, 'issued')`,
    [publisherId],
  );

  logger.info({ msg: 'publisher onboarded', publisherId });

  // API key shown ONCE — not stored in plaintext
  res.status(201).json({
    publisher_id: publisherId,
    api_key: apiKey,
    api_key_prefix: prefix,
    message: 'Store this API key — it will not be shown again.',
  });
});

// GET /v1/publishers/:id
publishersRouter.get('/:id', advertiserJwtAuth, requireRole('admin'), async (req: Request, res: Response): Promise<void> => {
  const pool = getPool();
  const { rows } = await pool.query(
    'SELECT publisher_id, name, contact_email, api_key_prefix, status, created_at FROM publishers WHERE publisher_id = $1',
    [req.params['id']],
  );
  if (!rows[0]) { res.status(404).json({ error: 'NOT_FOUND', message: 'Publisher not found' }); return; }
  res.json(rows[0]);
});

// POST /v1/publishers/:id/rotate-key
publishersRouter.post('/:id/rotate-key', advertiserJwtAuth, requireRole('admin'), async (req: Request, res: Response): Promise<void> => {
  const pool = getPool();
  const { apiKey, prefix, hash } = await generateApiKey();

  const result = await pool.query(
    `UPDATE publishers SET api_key_hash = $1, api_key_prefix = $2 WHERE publisher_id = $3 AND status = 'active' RETURNING publisher_id`,
    [hash, prefix, req.params['id']],
  );
  if (result.rowCount === 0) { res.status(404).json({ error: 'NOT_FOUND', message: 'Publisher not found or inactive' }); return; }

  await pool.query(`INSERT INTO api_key_events (publisher_id, event_type) VALUES ($1, 'rotated')`, [req.params['id']]);

  res.json({ publisher_id: req.params['id'], api_key: apiKey, api_key_prefix: prefix, message: 'Store this API key — it will not be shown again.' });
});

async function generateApiKey(): Promise<{ apiKey: string; prefix: string; hash: string }> {
  const raw = config.auth.apiKeyPrefix + crypto.randomBytes(32).toString('base64url');
  const prefix = raw.slice(0, 8);
  const hash = await bcrypt.hash(raw, 10);
  return { apiKey: raw, prefix, hash };
}
