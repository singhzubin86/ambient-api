/**
 * Publisher self-service reporting routes
 * Spec: AMBIENT_PROTOTYPE_SPECS.md R3 SPEC-6
 *
 * GET /v1/portal/publishers/me/stats              — impressions, clicks, CTR, spend
 * GET /v1/portal/publishers/me/integration-status — live | no_signal | not_integrated
 *
 * Source of truth: Log Store (WAL/R2 NDJSON files) — never Redis counters.
 * Beta implementation: reads WAL file directly (file aggregation before R2 is queryable).
 * Production: query R2 NDJSON files by date prefix.
 *
 * Query params for /stats:
 *   start_date — ISO date (YYYY-MM-DD), default: 30 days ago
 *   end_date   — ISO date (YYYY-MM-DD), default: today
 */
import { Router, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { getPool } from '../../db/pool';
import { logger } from '../../lib/logger';
import { portalAuth, requirePortalRole } from '../../middleware/portal-auth-middleware';
import { PortalJwtPayload } from '../../lib/portal-auth';
import { LogRecord } from '../../services/log-store';

export const portalReportingRouter = Router();

portalReportingRouter.use(portalAuth);
portalReportingRouter.use(requirePortalRole('publisher', 'both'));

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Parse ISO date string to start-of-day UTC ms */
function dateToMs(dateStr: string, endOfDay = false): number {
  const d = new Date(dateStr + 'T00:00:00Z');
  if (isNaN(d.getTime())) return NaN;
  if (endOfDay) d.setUTCHours(23, 59, 59, 999);
  return d.getTime();
}

/** Read all WAL records for a publisher from the local WAL file (beta path) */
function readWalRecords(publisherId: string, startMs: number, endMs: number): {
  impressions: LogRecord[];
  clicks: LogRecord[];
} {
  const walDir = process.env['WAL_DIR'] ?? '/data/wal';
  const walFile = path.join(walDir, 'pending.wal');

  const impressions: LogRecord[] = [];
  const clicks: LogRecord[] = [];

  if (!fs.existsSync(walFile)) return { impressions, clicks };

  try {
    const lines = fs.readFileSync(walFile, 'utf8').split('\n').filter(Boolean);
    for (const line of lines) {
      let record: LogRecord;
      try { record = JSON.parse(line) as LogRecord; } catch { continue; }

      if (record.publisher_id !== publisherId) continue;
      if (record.timestamp_utc_ms < startMs || record.timestamp_utc_ms > endMs) continue;

      if (record.event_type === 'impression') impressions.push(record);
      else if (record.event_type === 'click') clicks.push(record);
    }
  } catch (err) {
    logger.warn({ msg: 'reporting: WAL read failed', err: (err as Error).message });
  }

  return { impressions, clicks };
}

/** Group impressions/clicks by UTC date (YYYY-MM-DD) */
function groupByDate(records: LogRecord[]): Map<string, LogRecord[]> {
  const map = new Map<string, LogRecord[]>();
  for (const r of records) {
    const d = new Date(r.timestamp_utc_ms).toISOString().slice(0, 10);
    if (!map.has(d)) map.set(d, []);
    map.get(d)!.push(r);
  }
  return map;
}

// ── GET /v1/portal/publishers/me/stats ───────────────────────────────────────
portalReportingRouter.get('/me/stats', async (req: Request, res: Response): Promise<void> => {
  const jwtUser: PortalJwtPayload = (req as any).portalUser;
  const pool = getPool();

  // Resolve publisher_id from portal_user_id
  const { rows } = await pool.query(
    `SELECT publisher_id, cpm_usd FROM publishers WHERE portal_user_id = $1 AND status = 'active'`,
    [jwtUser.sub],
  );
  const pub = rows[0];
  if (!pub) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'No active publisher record found' });
    return;
  }

  // Parse + validate date range
  const today = new Date().toISOString().slice(0, 10);
  const thirtyAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const startDate = (req.query['start_date'] as string | undefined) ?? thirtyAgo;
  const endDate = (req.query['end_date'] as string | undefined) ?? today;

  const startMs = dateToMs(startDate);
  const endMs = dateToMs(endDate, true);

  if (isNaN(startMs) || isNaN(endMs)) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { date: 'start_date and end_date must be ISO dates (YYYY-MM-DD)' } });
    return;
  }
  if (startMs > endMs) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { date: 'start_date must be before end_date' } });
    return;
  }

  const { impressions, clicks } = readWalRecords(pub.publisher_id, startMs, endMs);

  // Build per-day rows
  const impressionsByDay = groupByDate(impressions);
  const clicksByDay = groupByDate(clicks);

  const allDays = new Set([...impressionsByDay.keys(), ...clicksByDay.keys()]);
  const cpmUsd = parseFloat(pub.cpm_usd);

  const rows_out: Array<{
    date: string;
    impressions: number;
    clicks: number;
    ctr: number;
    spend_usd: number;
  }> = [];

  for (const date of Array.from(allDays).sort()) {
    const imp = impressionsByDay.get(date)?.length ?? 0;
    const clk = clicksByDay.get(date)?.length ?? 0;
    const ctr = imp > 0 ? clk / imp : 0;
    const spend_usd = (imp * cpmUsd) / 1000;  // CPM = cost per 1000 impressions
    rows_out.push({ date, impressions: imp, clicks: clk, ctr: Math.round(ctr * 10000) / 10000, spend_usd: Math.round(spend_usd * 10000) / 10000 });
  }

  const totalImpressions = impressions.length;
  const totalClicks = clicks.length;
  const overallCtr = totalImpressions > 0 ? totalClicks / totalImpressions : 0;
  const totalSpendUsd = (totalImpressions * cpmUsd) / 1000;

  res.json({
    publisher_id: pub.publisher_id,
    start_date: startDate,
    end_date: endDate,
    summary: {
      total_impressions: totalImpressions,
      total_clicks: totalClicks,
      overall_ctr: Math.round(overallCtr * 10000) / 10000,
      total_spend_usd: Math.round(totalSpendUsd * 10000) / 10000,
    },
    rows: rows_out,
  });
});

// ── GET /v1/portal/publishers/me/integration-status ──────────────────────────
// live         = impression event in Log Store within last 48h
// no_signal    = impression event exists but none within last 48h
// not_integrated = no impression events at all
portalReportingRouter.get('/me/integration-status', async (req: Request, res: Response): Promise<void> => {
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

  const walDir = process.env['WAL_DIR'] ?? '/data/wal';
  const walFile = path.join(walDir, 'pending.wal');
  const fortyEightHoursAgoMs = Date.now() - 48 * 60 * 60 * 1000;

  let anyImpression = false;
  let recentImpression = false;

  if (fs.existsSync(walFile)) {
    try {
      const lines = fs.readFileSync(walFile, 'utf8').split('\n').filter(Boolean);
      for (const line of lines) {
        let record: LogRecord;
        try { record = JSON.parse(line) as LogRecord; } catch { continue; }
        if (record.publisher_id !== pub.publisher_id) continue;
        if (record.event_type !== 'impression') continue;
        anyImpression = true;
        if (record.timestamp_utc_ms >= fortyEightHoursAgoMs) {
          recentImpression = true;
          break; // No need to scan further
        }
      }
    } catch (err) {
      logger.warn({ msg: 'integration-status: WAL read failed', err: (err as Error).message });
    }
  }

  let status: 'live' | 'no_signal' | 'not_integrated';
  if (recentImpression) status = 'live';
  else if (anyImpression) status = 'no_signal';
  else status = 'not_integrated';

  res.json({
    publisher_id: pub.publisher_id,
    integration_status: status,
    checked_at: new Date().toISOString(),
  });
});
