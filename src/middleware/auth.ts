/**
 * Auth middleware — publisher API key + advertiser JWT
 * Spec: AMBIENT_ARCHITECTURE_V1.md §4.1, §4.2
 */
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { getRedis } from '../db/redis';
import { getPool } from '../db/pool';
import { config } from '../lib/config';
import { logger } from '../lib/logger';
import { JwtPayload } from '../types';

const KEY_CACHE_TTL_MS = 5 * 60 * 1000; // 5 min LRU cache per spec §3

// In-process LRU for API key validation — no DB hit on hot path
const _keyCache = new Map<string, { valid: boolean; publisherId: string; ts: number }>();

export async function publisherApiKeyAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Missing API key' });
    return;
  }
  const apiKey = header.slice(7);

  // LRU cache check
  const cached = _keyCache.get(apiKey);
  if (cached && Date.now() - cached.ts < KEY_CACHE_TTL_MS) {
    if (!cached.valid) {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid API key' });
      return;
    }
    (req as any).publisherId = cached.publisherId;
    next();
    return;
  }

  // DB lookup — hash the key and compare
  try {
    const bcrypt = await import('bcryptjs');
    const pool = getPool();
    // Fetch by prefix (first 8 chars) to limit candidate rows
    const prefix = apiKey.slice(0, 8);
    const { rows } = await pool.query(
      `SELECT publisher_id, api_key_hash FROM publishers WHERE api_key_prefix = $1 AND status = 'active'`,
      [prefix],
    );
    let found: { publisher_id: string } | null = null;
    for (const row of rows) {
      if (await bcrypt.compare(apiKey, row.api_key_hash)) {
        found = row;
        break;
      }
    }
    if (!found) {
      _keyCache.set(apiKey, { valid: false, publisherId: '', ts: Date.now() });
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid API key' });
      return;
    }
    _keyCache.set(apiKey, { valid: true, publisherId: found.publisher_id, ts: Date.now() });
    (req as any).publisherId = found.publisher_id;
    next();
  } catch (err) {
    logger.error({ msg: 'API key auth error', err: (err as Error).message });
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Auth check failed' });
  }
}

export function advertiserJwtAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Missing token' });
    return;
  }
  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, config.auth.jwtSecret) as JwtPayload;
    (req as any).jwtPayload = payload;
    next();
  } catch {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid or expired token' });
  }
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const payload: JwtPayload = (req as any).jwtPayload;
    if (!payload || !roles.includes(payload.role)) {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions' });
      return;
    }
    next();
  };
}
