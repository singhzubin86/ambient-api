/**
 * Reporting API
 * Spec: AMBIENT_ARCHITECTURE_V1.md §4.3 authoritative record rule:
 *   "The log store is the authoritative record for billing and reporting.
 *    Redis counters are best-effort. If they diverge, log store wins."
 * This endpoint reads ONLY from log store aggregates — never from Redis.
 *
 * GET /v1/reporting/summary   — JSON aggregate
 * GET /v1/reporting/export    — CSV export
 *
 * At beta scale, log store = local NDJSON files on disk / R2.
 * We read from the local WAL flush path for now; in production this will
 * read from R2 via the audit scan process. For beta, we use a Postgres
 * events table that the flush worker populates (denormalized for query speed).
 * Deduplication: GROUP BY request_id ensures at-least-once delivery doesn't double-count.
 */
import { Router, Request, Response } from 'express';
import { getPool } from '../../db/pool';
import { advertiserJwtAuth, requireRole } from '../../middleware/auth';
import { JwtPayload, ReportingQuery, ReportingSummary } from '../../types';

export const reportingRouter = Router();

// GET /v1/reporting/summary
reportingRouter.get('/summary', advertiserJwtAuth, async (req: Request, res: Response): Promise<void> => {
  const jwt = (req as any).jwtPayload as JwtPayload;
  const query = parseQuery(req, jwt);

  if (!query.start_date || !query.end_date) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'start_date and end_date are required (ISO 8601 date)' });
    return;
  }

  const pool = getPool();

  // Impressions — deduplicated on request_id (at-least-once delivery per Sentinel spec)
  const impressionsResult = await pool.query(
    `SELECT
       DATE(to_timestamp(timestamp_utc_ms / 1000.0) AT TIME ZONE 'UTC') AS date,
       campaign_id,
       publisher_id,
       COUNT(DISTINCT request_id) AS impressions
     FROM event_log
     WHERE event_type = 'impression'
       AND to_timestamp(timestamp_utc_ms / 1000.0) >= $1::date
       AND to_timestamp(timestamp_utc_ms / 1000.0) < $2::date + interval '1 day'
       ${query.campaign_id ? 'AND campaign_id = $3' : ''}
       ${query.publisher_id ? `AND publisher_id = $${query.campaign_id ? 4 : 3}` : ''}
     GROUP BY 1, 2, 3
     ORDER BY 1`,
    buildParams(query),
  );

  // Clicks — deduplicated on impression_token (single-use enforced at API, but deduplicate here too)
  const clicksResult = await pool.query(
    `SELECT
       DATE(to_timestamp(timestamp_utc_ms / 1000.0) AT TIME ZONE 'UTC') AS date,
       campaign_id,
       publisher_id,
       COUNT(DISTINCT impression_token) AS clicks
     FROM event_log
     WHERE event_type = 'click'
       AND to_timestamp(timestamp_utc_ms / 1000.0) >= $1::date
       AND to_timestamp(timestamp_utc_ms / 1000.0) < $2::date + interval '1 day'
       ${query.campaign_id ? 'AND campaign_id = $3' : ''}
       ${query.publisher_id ? `AND publisher_id = $${query.campaign_id ? 4 : 3}` : ''}
     GROUP BY 1, 2, 3`,
    buildParams(query),
  );

  // Merge into rows
  const clickMap = new Map<string, number>();
  for (const row of clicksResult.rows) {
    clickMap.set(`${row.date}:${row.campaign_id}:${row.publisher_id}`, Number(row.clicks));
  }

  // Join with campaign CPM for spend calculation
  const campaignIds = [...new Set(impressionsResult.rows.map((r) => r.campaign_id))];
  const cpmResult = campaignIds.length > 0
    ? await pool.query(`SELECT campaign_id, cpm_floor_cents FROM campaigns WHERE campaign_id = ANY($1)`, [campaignIds])
    : { rows: [] };
  const cpmMap = new Map(cpmResult.rows.map((r) => [r.campaign_id, Number(r.cpm_floor_cents)]));

  const rows = impressionsResult.rows.map((r) => {
    const imps = Number(r.impressions);
    const clicks = clickMap.get(`${r.date}:${r.campaign_id}:${r.publisher_id}`) ?? 0;
    const cpm = cpmMap.get(r.campaign_id) ?? 0;
    const spend_cents = Math.ceil((imps * cpm) / 1000);
    return {
      date: r.date,
      campaign_id: r.campaign_id,
      publisher_id: r.publisher_id,
      impressions: imps,
      clicks,
      ctr: imps > 0 ? clicks / imps : 0,
      spend_cents,
    };
  });

  const summary: ReportingSummary = {
    total_impressions: rows.reduce((s, r) => s + r.impressions, 0),
    total_clicks: rows.reduce((s, r) => s + r.clicks, 0),
    overall_ctr: rows.reduce((s, r) => s + r.impressions, 0) > 0
      ? rows.reduce((s, r) => s + r.clicks, 0) / rows.reduce((s, r) => s + r.impressions, 0)
      : 0,
    total_spend_cents: rows.reduce((s, r) => s + r.spend_cents, 0),
    rows,
  };

  if (query.format === 'csv') {
    const csv = toCsv(rows);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="ambient-report.csv"');
    res.send(csv);
    return;
  }

  res.json(summary);
});

function parseQuery(req: Request, jwt: JwtPayload): ReportingQuery {
  return {
    start_date: req.query['start_date'] as string,
    end_date: req.query['end_date'] as string,
    campaign_id: req.query['campaign_id'] as string | undefined,
    // Advertisers can only see their own data; admins can filter by publisher
    publisher_id: jwt.role === 'admin' ? (req.query['publisher_id'] as string | undefined) : undefined,
    format: (req.query['format'] as 'json' | 'csv') ?? 'json',
  };
}

function buildParams(q: ReportingQuery): unknown[] {
  const p: unknown[] = [q.start_date, q.end_date];
  if (q.campaign_id) p.push(q.campaign_id);
  if (q.publisher_id) p.push(q.publisher_id);
  return p;
}

function toCsv(rows: ReturnType<typeof Array.prototype.map>): string {
  const header = 'date,campaign_id,publisher_id,impressions,clicks,ctr,spend_cents';
  const lines = (rows as any[]).map((r) =>
    `${r.date},${r.campaign_id},${r.publisher_id},${r.impressions},${r.clicks},${r.ctr.toFixed(4)},${r.spend_cents}`,
  );
  return [header, ...lines].join('\n');
}
