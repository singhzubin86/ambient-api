/**
 * Frequency Cap Service
 * Signal Decision 1 + Socket session_token spec:
 *   Redis key: fc:{publisher_id}:{session_token}:{campaign_id}
 *   TTL: 1800s (sliding)
 *   Hard cap: 2 impressions per campaign per session window
 *   Exceeded: exclude campaign from candidate set
 *
 * session_token format: ^[a-zA-Z0-9_-]{1,128}$  (validated at intake, not here)
 */
import { getRedis } from '../db/redis';
import { config } from '../lib/config';

const { ttlSeconds, hardCap } = config.freqCap;

export const SESSION_TOKEN_PATTERN = /^[a-zA-Z0-9_-]{1,128}$/;

function key(publisherId: string, sessionToken: string, campaignId: string): string {
  return `fc:${publisherId}:${sessionToken}:${campaignId}`;
}

/** Returns true if the campaign should be excluded from the candidate set. */
export async function isFreqCapExceeded(
  publisherId: string,
  sessionToken: string,
  campaignId: string,
): Promise<boolean> {
  const redis = getRedis();
  const val = await redis.get(key(publisherId, sessionToken, campaignId));
  return val !== null && parseInt(val, 10) >= hardCap;
}

/** Increment counter with sliding TTL. Call after impression is selected. */
export async function recordFreqCapImpression(
  publisherId: string,
  sessionToken: string,
  campaignId: string,
): Promise<void> {
  const redis = getRedis();
  const k = key(publisherId, sessionToken, campaignId);
  const pipeline = redis.pipeline();
  pipeline.incr(k);
  pipeline.expire(k, ttlSeconds); // sliding window
  await pipeline.exec();
}
