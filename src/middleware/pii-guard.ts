/**
 * PII Guard Middleware
 *
 * Blueprint/Relay requirement (2026-08-09):
 * Active rejection of PII field names at the intake layer — not just schema omission.
 * Rejected field names: user_id, email, device_id, ip
 * Rejections logged as policy violations to log store.
 *
 * Also covers context.keywords PII pattern detection (crypto.ts containsPii).
 */
import { Request, Response, NextFunction } from 'express';
import { containsPii } from '../lib/crypto';
import { appendRecord } from '../services/log-store';
import { logger } from '../lib/logger';

// Hard-banned field names in request body (Blueprint requirement)
const BANNED_FIELDS = ['user_id', 'email', 'device_id', 'ip'] as const;

export function piiFieldGuard(req: Request, res: Response, next: NextFunction): void {
  if (!req.body || typeof req.body !== 'object') { next(); return; }

  const found = BANNED_FIELDS.filter((f) => f in req.body);
  if (found.length > 0) {
    const publisherId: string = (req as any).publisherId ?? 'unknown';
    logger.warn({ msg: 'PII_POLICY_VIOLATION', fields: found, publisherId, path: req.path });
    // Log as policy violation (non-blocking, best-effort)
    try {
      appendRecord({
        event_type: 'anomaly_flag',
        timestamp_utc_ms: Date.now(),
        publisher_id: publisherId,
        alert_type: 'pii_field_rejection',
        action: 'reject_request',
      });
    } catch { /* never block the response path for logging errors */ }

    res.status(400).json({
      error: 'PII_FIELD_REJECTED',
      message: `Request contains prohibited fields: ${found.join(', ')}. No PII is accepted in the ad request path.`,
      request_id: req.body.request_id,
    });
    return;
  }
  next();
}

/** Validate context.keywords array for PII patterns. */
export function piiKeywordsGuard(req: Request, res: Response, next: NextFunction): void {
  const keywords: unknown = req.body?.context?.keywords;
  if (!Array.isArray(keywords)) { next(); return; }

  if (containsPii(keywords as string[])) {
    const publisherId: string = (req as any).publisherId ?? 'unknown';
    logger.warn({ msg: 'PII_KEYWORDS_DETECTED', publisherId, path: req.path });
    try {
      appendRecord({
        event_type: 'anomaly_flag',
        timestamp_utc_ms: Date.now(),
        publisher_id: publisherId,
        alert_type: 'pii_keywords_detected',
        action: 'reject_request',
      });
    } catch { /* never block response */ }

    res.status(400).json({
      error: 'PII_DETECTED_IN_KEYWORDS',
      message: 'Context keywords appear to contain PII. Only topic/keyword strings are accepted — no user data.',
      request_id: req.body?.request_id,
    });
    return;
  }
  next();
}
