/**
 * GET /v1/ads/click?token=<impression_token>
 * Sentinel Decision 3:
 *  - Validate HMAC + 24h expiry window
 *  - Single-use enforcement: click_seen:<sha256(token)> in Redis TTL 86400s
 *  - If already seen: log duplicate-click anomaly, redirect anyway, DO NOT write click event
 *  - Async: append click event to log store
 *  - Async: increment Redis click counter
 *  - Return 302 → advertiser destination URL
 */
import { Router, Request, Response } from 'express';
import { validateImpressionToken } from '../../lib/crypto';
import { sha256Hex } from '../../lib/crypto';
import { getRedis } from '../../db/redis';
import { getPool } from '../../db/pool';
import { appendRecord } from '../../services/log-store';
import { logger } from '../../lib/logger';

export const adsClickRouter = Router();

adsClickRouter.get('/click', async (req: Request, res: Response): Promise<void> => {
  const token = req.query['token'] as string | undefined;

  if (!token) {
    res.status(400).json({ error: 'MISSING_TOKEN', message: 'token query parameter required' });
    return;
  }

  // ── 1. Validate token (HMAC + 24h expiry) ────────────────────────────────
  let payload: ReturnType<typeof validateImpressionToken>;
  try {
    payload = validateImpressionToken(token);
  } catch (err) {
    const reason = (err as Error).message;
    // Log expired/invalid token attempts as anomaly
    if (reason === 'TOKEN_EXPIRED' || reason === 'INVALID_TOKEN_SIGNATURE') {
      setImmediate(() => {
        try {
          appendRecord({
            event_type: 'anomaly_flag',
            timestamp_utc_ms: Date.now(),
            publisher_id: 'unknown',
            alert_type: reason === 'TOKEN_EXPIRED' ? 'expired_token_click' : 'invalid_token_click',
            action: 'reject_click',
          });
        } catch { /* never block */ }
      });
    }
    res.status(400).json({ error: 'INVALID_TOKEN', message: reason });
    return;
  }

  // ── 2. Single-use enforcement (Sentinel Decision 3, addition 2) ───────────
  const tokenHash = sha256Hex(token);
  const redis = getRedis();
  const seenKey = `click_seen:${tokenHash}`;
  const alreadySeen = await redis.set(seenKey, '1', 'EX', 86400, 'NX') === null;

  if (alreadySeen) {
    // Log duplicate-click anomaly, but still redirect (don't break UX)
    setImmediate(() => {
      try {
        appendRecord({
          event_type: 'anomaly_flag',
          timestamp_utc_ms: Date.now(),
          publisher_id: payload.publisher_id,
          campaign_id: payload.campaign_id,
          impression_token: token,
          alert_type: 'duplicate_click',
          action: 'redirect_only_no_log',
        });
      } catch { /* never block */ }
    });
    // Still redirect — don't show user an error
    // Need destination URL — fetch from campaign record
    const destUrl = await getDestinationUrl(payload.campaign_id);
    res.redirect(302, destUrl);
    return;
  }

  // ── 3. Async: write click event to log store ──────────────────────────────
  setImmediate(() => {
    try {
      appendRecord({
        event_type: 'click',
        timestamp_utc_ms: Date.now(),
        publisher_id: payload.publisher_id,
        campaign_id: payload.campaign_id,
        impression_token: token,
      });
    } catch (err) {
      logger.error({ msg: 'click log failed', err: (err as Error).message });
    }
  });

  // ── 4. Async: increment Redis click counter ────────────────────────────────
  setImmediate(() => {
    void redis.incr(`clicks:${payload.campaign_id}:${new Date().toISOString().slice(0, 10)}`);
  });

  // ── 5. 302 redirect ───────────────────────────────────────────────────────
  const destUrl = await getDestinationUrl(payload.campaign_id);
  res.redirect(302, destUrl);
});

async function getDestinationUrl(campaignId: string): Promise<string> {
  try {
    const pool = getPool();
    const { rows } = await pool.query(
      'SELECT destination_url FROM campaigns WHERE campaign_id = $1',
      [campaignId],
    );
    return rows[0]?.destination_url ?? 'https://ambient.example';
  } catch {
    return 'https://ambient.example';
  }
}
