/**
 * Anomaly Monitor
 * Signal Decision 4 + Sentinel CTR addition:
 *
 * Alert condition 1 — Impression rate:
 *   Any 5-min rolling window where publisher impressions > 3× trailing 7-day median
 *   Bootstrap (days 0–6): absolute cap 100 impressions / 5-min window
 *
 * Alert condition 2 — CTR (Signal/Sentinel correction 2026-08-09):
 *   CTR > 5% in any 5-min rolling window, minimum 10 impressions in window
 *
 * Both alerts: write JSON record to log store + operator notification log.
 * No auto-blocking at v1. Sentinel owns response.
 *
 * Runs as a background process — NOT on the hot path.
 * Poll interval: 5 minutes (matches window size).
 */
import { getPool } from '../db/pool';
import { appendRecord } from './log-store';
import { config } from '../lib/config';
import { logger } from '../lib/logger';

const WINDOW_MINUTES = config.anomaly.windowMinutes;         // 5
const SPIKE_MULTIPLIER = config.anomaly.spikeMultiplier;     // 3.0
const BOOTSTRAP_DAYS = config.anomaly.bootstrapDays;         // 7
const BOOTSTRAP_CAP = config.anomaly.bootstrapAbsoluteCap;   // 100
const TRAILING_DAYS = config.anomaly.trailingDays;           // 7

// CTR anomaly (Signal/Sentinel correction 2026-08-09)
const CTR_ALERT_THRESHOLD = 0.05;   // 5%
const CTR_MIN_IMPRESSIONS = 10;      // floor: at least 10 impressions in window

let _monitorTimer: NodeJS.Timeout | null = null;

export function startAnomalyMonitor(): void {
  if (_monitorTimer) return;
  _monitorTimer = setInterval(() => { void runCheck(); }, WINDOW_MINUTES * 60 * 1000);
  if (_monitorTimer.unref) _monitorTimer.unref();
  logger.info({ msg: 'anomaly-monitor: started', windowMinutes: WINDOW_MINUTES });
}

export function stopAnomalyMonitor(): void {
  if (_monitorTimer) { clearInterval(_monitorTimer); _monitorTimer = null; }
}

async function runCheck(): Promise<void> {
  try {
    const pool = getPool();
    const windowStart = Date.now() - WINDOW_MINUTES * 60 * 1000;
    const windowStartMs = windowStart;

    // ── Get per-publisher counts in current 5-min window ─────────────────
    const windowResult = await pool.query<{
      publisher_id: string;
      impression_count: string;
      click_count: string;
    }>(`
      SELECT
        publisher_id,
        COUNT(*) FILTER (WHERE event_type = 'impression') AS impression_count,
        COUNT(*) FILTER (WHERE event_type = 'click')      AS click_count
      FROM event_log
      WHERE timestamp_utc_ms >= $1
      GROUP BY publisher_id
    `, [windowStartMs]);

    for (const row of windowResult.rows) {
      const publisherId = row.publisher_id;
      const impCount = parseInt(row.impression_count, 10);
      const clickCount = parseInt(row.click_count, 10);

      // ── Alert condition 1: impression rate ──────────────────────────────
      await checkImpressionRate(pool, publisherId, impCount, windowStartMs);

      // ── Alert condition 2: CTR > 5% (floor: 10 impressions) ────────────
      if (impCount >= CTR_MIN_IMPRESSIONS) {
        const ctr = clickCount / impCount;
        if (ctr > CTR_ALERT_THRESHOLD) {
          const alertRecord = {
            alert_type: 'ctr_anomaly',
            publisher_id: publisherId,
            window_start_utc_ms: windowStartMs,
            window_impression_count: impCount,
            window_click_count: clickCount,
            ctr,
            threshold: CTR_ALERT_THRESHOLD,
            action: 'notify_operator',
          };
          logger.warn({ msg: 'ANOMALY_CTR', ...alertRecord });
          appendRecord({ event_type: 'anomaly_flag', timestamp_utc_ms: Date.now(), ...alertRecord });
        }
      }
    }
  } catch (err) {
    logger.error({ msg: 'anomaly-monitor: check failed', err: (err as Error).message });
  }
}

async function checkImpressionRate(
  pool: ReturnType<typeof getPool>,
  publisherId: string,
  impCount: number,
  windowStartMs: number,
): Promise<void> {
  // Determine how many days of data exist for this publisher
  const ageResult = await pool.query<{ first_event_ms: string }>(
    `SELECT MIN(timestamp_utc_ms) AS first_event_ms FROM event_log WHERE publisher_id = $1 AND event_type = 'impression'`,
    [publisherId],
  );
  const firstEventMs = parseInt(ageResult.rows[0]?.first_event_ms ?? '0', 10);
  const agedays = (Date.now() - firstEventMs) / (24 * 60 * 60 * 1000);

  let threshold: number;
  let baselineMedian: number | null = null;

  if (agedays < BOOTSTRAP_DAYS) {
    // Bootstrap mode: absolute cap
    threshold = BOOTSTRAP_CAP;
  } else {
    // Trailing 7-day median per 5-min slot
    const medianResult = await pool.query<{ median_count: string }>(`
      SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY cnt) AS median_count
      FROM (
        SELECT
          floor(timestamp_utc_ms / (${WINDOW_MINUTES} * 60 * 1000)) AS slot,
          COUNT(*) AS cnt
        FROM event_log
        WHERE publisher_id = $1
          AND event_type = 'impression'
          AND timestamp_utc_ms >= $2
          AND timestamp_utc_ms < $3
        GROUP BY slot
      ) AS slots
    `, [
      publisherId,
      Date.now() - TRAILING_DAYS * 24 * 60 * 60 * 1000,
      windowStartMs,
    ]);

    baselineMedian = parseFloat(medianResult.rows[0]?.median_count ?? '0');
    threshold = baselineMedian * SPIKE_MULTIPLIER;
  }

  if (impCount > threshold) {
    const alertRecord = {
      alert_type: 'impression_rate_anomaly',
      publisher_id: publisherId,
      window_start_utc_ms: windowStartMs,
      window_impression_count: impCount,
      baseline_median: baselineMedian ?? 0,
      ratio: baselineMedian ? impCount / baselineMedian : 0,
      threshold: SPIKE_MULTIPLIER,
      action: 'notify_operator',
    };
    logger.warn({ msg: 'ANOMALY_IMPRESSION_RATE', ...alertRecord });
    appendRecord({ event_type: 'anomaly_flag', timestamp_utc_ms: Date.now(), ...alertRecord });
  }
}
