/**
 * POST /v1/ads/request — Ad Decisioning Hot Path
 *
 * Pipeline (Signal Decision 3):
 *  1. Auth + rate limit (middleware)
 *  2. PII field guard + PII keywords guard (middleware)
 *  3. session_token format validation (Socket spec: ^[a-zA-Z0-9_-]{1,128}$)
 *  4. Load active campaign cache (in-process, no DB)
 *  5. Filter: status=active, within flight dates
 *  6. Filter: daily budget gate (Redis, best-effort)
 *  7. Filter: freq cap gate (Redis fc:{pub}:{sess}:{camp}, cap=2)
 *  8. Filter: keyword match (Porter stem set intersection ≥1)
 *  9. Rank: cpm_floor DESC, created_at ASC
 * 10. Select top campaign → build ad object + disclosure fields
 * 11. Mint impression token (HMAC-SHA256, 24h validity)
 * 12. Async: append impression to log store (WAL-backed)
 * 13. Async: increment freq cap + spend counters
 * 14. Return 200 AdResponse or 204 No Content
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { publisherApiKeyAuth } from '../../middleware/auth';
import { piiFieldGuard, piiKeywordsGuard } from '../../middleware/pii-guard';
import { getCampaignArray, CachedCampaign } from '../../services/campaign-cache';
import { isFreqCapExceeded, recordFreqCapImpression, SESSION_TOKEN_PATTERN } from '../../services/freq-cap';
import { isDailyBudgetExhausted, recordImpressionSpend } from '../../services/budget-pacing';
import { stemKeywords, keywordsMatch } from '../../services/stemmer';
import { mintImpressionToken } from '../../lib/crypto';
import { appendRecord } from '../../services/log-store';
import { config } from '../../lib/config';
import { logger } from '../../lib/logger';
import { AdRequestBody, AdResponseHit, AdObject } from '../../types';

export const adsRequestRouter = Router();

adsRequestRouter.post(
  '/request',
  publisherApiKeyAuth,
  piiFieldGuard,
  piiKeywordsGuard,
  async (req: Request, res: Response): Promise<void> => {
    const startMs = Date.now();
    const publisherId: string = (req as any).publisherId;
    const body = req.body as AdRequestBody;

    // ── 1. Validate required fields ──────────────────────────────────────────
    const requestId = body.request_id ?? uuidv4();
    if (!body.session_token || !SESSION_TOKEN_PATTERN.test(body.session_token)) {
      res.status(400).json({
        error: 'INVALID_SESSION_TOKEN',
        message: 'session_token must be alphanumeric/hyphen/underscore, 1–128 chars',
        request_id: requestId,
      });
      return;
    }
    if (!Array.isArray(body.context?.keywords) || body.context.keywords.length === 0) {
      // P-1 (Proof): empty keywords array is a valid no-fill condition, not a protocol error.
      // Return 204 No Content (same as no matching campaign), not 400.
      if (Array.isArray(body.context?.keywords) && body.context.keywords.length === 0) {
        res.status(204).end();
      } else {
        res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'context.keywords is required and must be an array',
          request_id: requestId,
        });
      }
      return;
    }
    if (!body.context.surface) {
      res.status(400).json({ error: 'INVALID_REQUEST', message: 'context.surface is required', request_id: requestId });
      return;
    }

    const sessionToken = body.session_token;
    const requestKeywords = stemKeywords(body.context.keywords);
    const surface = body.context.surface;
    const now = new Date();

    // ── 2. Load in-process campaign cache ────────────────────────────────────
    const allCampaigns = getCampaignArray();

    // ── 3–8. Filter pipeline ─────────────────────────────────────────────────
    // Steps 3-5: status, flight dates, surface — pure in-process
    const flightEligible = allCampaigns.filter((c) => {
      if (c.status !== 'active') return false;
      if (now < c.flight_start || now > c.flight_end) return false;
      if (c.targeting_surfaces.length > 0 && !c.targeting_surfaces.includes(surface)) return false;
      return true;
    });

    // Steps 6-7: Redis gates (parallel for latency)
    const [budgetResults, freqCapResults] = await Promise.all([
      Promise.all(flightEligible.map((c) => isDailyBudgetExhausted(c.campaign_id, c.budget_daily_cents))),
      Promise.all(flightEligible.map((c) => isFreqCapExceeded(publisherId, sessionToken, c.campaign_id))),
    ]);

    const budgetEligible = flightEligible.filter((_, i) => !budgetResults[i]);
    const freqEligible = budgetEligible.filter((c) => {
      const idx = flightEligible.indexOf(c);
      return !freqCapResults[idx];
    });

    // Step 8: keyword match (in-process CPU, O(N×M))
    const matched = freqEligible.filter((c) =>
      keywordsMatch(requestKeywords, c.targeting_keywords_stemmed),
    );

    const candidateSetSize = matched.length;

    // ── 9. Rank: cpm_floor DESC, created_at ASC ──────────────────────────────
    matched.sort((a, b) => {
      if (b.cpm_floor_cents !== a.cpm_floor_cents) return b.cpm_floor_cents - a.cpm_floor_cents;
      return a.created_at.getTime() - b.created_at.getTime();
    });

    const winner: CachedCampaign | undefined = matched[0];

    // ── 10. No fill ───────────────────────────────────────────────────────────
    if (!winner) {
      res.status(204).end();
      return;
    }

    // ── 11. Mint impression token ─────────────────────────────────────────────
    const impressionId = uuidv4();
    const timestampMs = Date.now();
    const impressionToken = mintImpressionToken({
      impression_id: impressionId,
      publisher_id: publisherId,
      campaign_id: winner.campaign_id,
      timestamp_ms: timestampMs,
    });

    // ── 12. Build ad object + disclosure fields (Warden requirement) ──────────
    const clickUrl = `${process.env['API_BASE_URL'] ?? 'https://api.ambient.example'}/v1/ads/click?token=${encodeURIComponent(impressionToken)}`;

    const ad: AdObject = {
      headline: winner.headline,
      body: winner.body,
      cta_text: winner.cta_text,
      cta_url: clickUrl,
      disclosure_label: winner.disclosure_label,
      disclosure_placement: winner.disclosure_placement,
    };

    // ── 13. Async: log impression (WAL-backed — never blocks response) ────────
    const userAgentRaw = req.headers['user-agent'] ?? '';
    const userAgentHash = 'sha256:' + crypto.createHash('sha256').update(userAgentRaw).digest('hex');

    setImmediate(() => {
      try {
        appendRecord({
          event_type: 'impression',
          timestamp_utc_ms: timestampMs,
          publisher_id: publisherId,
          campaign_id: winner.campaign_id,
          ad_id: `${winner.campaign_id}:creative`,
          session_token: sessionToken,
          impression_token: impressionToken,
          request_id: requestId,
          surface,
          user_agent_hash: userAgentHash,
          candidate_set_size: candidateSetSize,
        });
      } catch (err) {
        logger.error({ msg: 'impression log failed', err: (err as Error).message, requestId });
      }
    });

    // ── 14. Async: update counters (best-effort Redis) ────────────────────────
    setImmediate(() => {
      void recordFreqCapImpression(publisherId, sessionToken, winner.campaign_id);
      void recordImpressionSpend(winner.campaign_id, winner.cpm_floor_cents);
    });

    // ── 15. Respond ───────────────────────────────────────────────────────────
    const latencyMs = Date.now() - startMs;
    if (latencyMs > 150) {
      logger.warn({ msg: 'LATENCY_BUDGET_EXCEEDED', latencyMs, requestId, threshold: 150 });
    }

    const response: AdResponseHit = {
      ad,
      impression_token: impressionToken,
      request_id: requestId,
    };
    res.status(200).json(response);
  },
);
