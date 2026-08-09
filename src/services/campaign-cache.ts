/**
 * Campaign In-Memory Cache
 * Spec: AMBIENT_ARCHITECTURE_V1.md §8
 *
 * Active campaigns are preloaded and refreshed every 30s (copy-on-write).
 * Hot path reads from this cache ONLY — zero DB I/O.
 * Budget pacing counters remain in Redis (shared across instances).
 */
import { getPool } from '../db/pool';
import { config } from '../lib/config';
import { logger } from '../lib/logger';

export interface CachedCampaign {
  campaign_id: string;
  advertiser_id: string;
  name: string;
  advertiser_category: string;
  status: string;
  headline: string;
  body: string;
  cta_text: string;
  destination_url: string;
  disclosure_label: 'Ad' | 'Sponsored';
  disclosure_placement: 'prepend' | 'surround';
  targeting_keywords: string[];
  targeting_keywords_stemmed: string[];  // pre-computed — Signal Decision 2
  targeting_surfaces: string[];
  budget_total_cents: number;
  budget_daily_cents: number;
  cpm_floor_cents: number;              // Signal Decision 3: ranking key
  flight_start: Date;
  flight_end: Date;
  created_at: Date;
}

// Immutable snapshot — swapped atomically on refresh (copy-on-write)
let _campaignMap: ReadonlyMap<string, CachedCampaign> = new Map();
let _refreshTimer: NodeJS.Timeout | null = null;

export function getCampaigns(): ReadonlyMap<string, CachedCampaign> {
  return _campaignMap;
}

export function getCampaignArray(): CachedCampaign[] {
  return Array.from(_campaignMap.values());
}

export async function loadCampaigns(): Promise<void> {
  const pool = getPool();
  const { rows } = await pool.query<CachedCampaign>(`
    SELECT
      campaign_id, advertiser_id, name, advertiser_category, status,
      headline, body, cta_text, destination_url,
      disclosure_label, disclosure_placement,
      targeting_keywords, targeting_keywords_stemmed, targeting_surfaces,
      budget_total_cents, budget_daily_cents, cpm_floor_cents,
      flight_start, flight_end, created_at
    FROM campaigns
    WHERE status = 'active'
    ORDER BY created_at ASC
  `);

  const next = new Map<string, CachedCampaign>();
  for (const row of rows) {
    next.set(row.campaign_id, {
      ...row,
      flight_start: new Date(row.flight_start),
      flight_end: new Date(row.flight_end),
      created_at: new Date(row.created_at),
    });
  }
  // Atomic swap — copy-on-write
  _campaignMap = next;
  logger.debug({ msg: 'campaign cache refreshed', count: next.size });
}

export function startCampaignCacheRefresh(): void {
  if (_refreshTimer) return;
  _refreshTimer = setInterval(async () => {
    try {
      await loadCampaigns();
    } catch (err) {
      logger.error({ msg: 'campaign cache refresh failed', err: (err as Error).message });
    }
  }, config.campaign.cacheTtlMs);
  _refreshTimer.unref(); // don't block process exit
}

export function stopCampaignCacheRefresh(): void {
  if (_refreshTimer) {
    clearInterval(_refreshTimer);
    _refreshTimer = null;
  }
}
