/**
 * Budget Pacing Service
 * Signal Decision 3: binary gate — campaigns at daily cap excluded before scoring.
 * Redis counters are best-effort for real-time control only.
 * Log store is authoritative for billing (enforced in Reporting API).
 */
import { getRedis } from '../db/redis';

// Key: bp:daily:{campaign_id}:{YYYY-MM-DD-UTC}
function dailyKey(campaignId: string): string {
  const d = new Date();
  const date = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
  return `bp:daily:${campaignId}:${date}`;
}

/** Returns true if daily budget is exhausted (best-effort Redis check). */
export async function isDailyBudgetExhausted(
  campaignId: string,
  dailyBudgetCents: number,
): Promise<boolean> {
  const redis = getRedis();
  const val = await redis.get(dailyKey(campaignId));
  if (val === null) return false;
  return parseInt(val, 10) >= dailyBudgetCents;
}

/**
 * Record spend for an impression (CPM-based).
 * cpmFloorCents / 1000 = cost per impression in cents.
 */
export async function recordImpressionSpend(
  campaignId: string,
  cpmFloorCents: number,
): Promise<void> {
  const redis = getRedis();
  const k = dailyKey(campaignId);
  const costCents = Math.ceil(cpmFloorCents / 1000);
  const pipeline = redis.pipeline();
  pipeline.incrby(k, costCents);
  // TTL: expire at end of day + 1h buffer
  const secondsUntilMidnight = secondsToMidnightUtc();
  pipeline.expire(k, secondsUntilMidnight + 3600);
  await pipeline.exec();
}

function secondsToMidnightUtc(): number {
  const now = new Date();
  const midnight = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  return Math.ceil((midnight.getTime() - now.getTime()) / 1000);
}
