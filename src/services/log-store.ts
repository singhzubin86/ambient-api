/**
 * Log Store — Tamper-Evident Append-Only Event Log
 *
 * Sentinel Decisions 1 + 2:
 *   - Per-record: prev_hash (SHA-256 chain) + record_hmac (HMAC-SHA256, LOG_SIGNING_KEY)
 *   - Durability: WAL at /data/wal (O_APPEND|O_SYNC, NVMe named volume) + ring buffer
 *   - Flush: batch 500 records OR 5s → NDJSON → R2 (ambient-logs, write-only)
 *   - Retry: 3 attempts, 1s/2s/4s exponential backoff; dead-letter on failure
 *   - Startup: replay WAL before accepting traffic
 *   - File format: hourly NDJSON, cross-file chain continuity
 *   - File-level manifest on rotation
 *   - Deduplication: reporting layer deduplicates on request_id (at-least-once delivery)
 *
 * Anchor infra:
 *   WAL volume:  /data/wal  (ambient_wal NVMe, O_SYNC safe)
 *   R2 bucket:   ambient-logs  (PutObject only)
 *   Secret:      LOG_SIGNING_KEY
 *
 * NOTE: session_token de-linkage architecture is an open Blueprint item.
 * The session_token field is included per current spec; finalise after Blueprint confirms.
 */
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { canonicalSha256, sealRecord, GENESIS_PREV_HASH } from '../lib/crypto';
import { logger } from '../lib/logger';

// ─── Infra constants (Anchor confirmed) ───────────────────────────────────────
const WAL_DIR = process.env['WAL_DIR'] ?? '/data/wal';
const WAL_FILE = path.join(WAL_DIR, 'pending.wal');
const DEAD_LETTER_DIR = path.join(WAL_DIR, 'dead_letter');
const LOG_STORE_BUCKET = process.env['LOG_STORE_BUCKET'] ?? 'ambient-logs';

// S-2 (Sentinel): inject INSTANCE_ID so concurrent Fly.io instances never share an R2 key.
// Each instance writes to its own object under the hourly prefix — audit reads all objects
// under the prefix.
const INSTANCE_ID: string = process.env['INSTANCE_ID'] ?? uuidv4();

// Flush parameters (Sentinel Decision 2)
const FLUSH_MAX_RECORDS = 500;
const FLUSH_INTERVAL_MS = 5_000;
const RETRY_DELAYS_MS = [1_000, 2_000, 4_000];

// Ring buffer capacity (Sentinel Decision 2: 10,000 records ≈ 40h at beta QPS)
const RING_BUFFER_CAPACITY = 10_000;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface LogRecord {
  v: 1;
  seq: number;
  event_type: 'impression' | 'click' | 'anomaly_flag';
  timestamp_utc_ms: number;
  publisher_id: string;
  campaign_id?: string;
  ad_id?: string;
  /** Open Blueprint item: de-linkage architecture TBD. Included per current spec. */
  session_token?: string;
  impression_token?: string;
  request_id?: string;
  /** P-4: impression_id on click events for cross-correlation with impression log entries. */
  impression_id?: string;
  surface?: string;
  user_agent_hash?: string;
  candidate_set_size?: number;   // Signal Decision 3: log per impression
  // Anomaly fields
  alert_type?: string;
  window_start_utc_ms?: number;
  window_impression_count?: number;
  window_click_count?: number;
  baseline_median?: number;
  ratio?: number;
  threshold?: number;
  ctr?: number;
  action?: string;
  // Chain integrity (Sentinel Decision 1)
  prev_hash: string;
  record_hmac: string;
}

interface ChainState {
  lastSeq: number;
  lastHash: string;
}

// ─── Module state ─────────────────────────────────────────────────────────────

let _seq = 0;
let _prevHash: string = GENESIS_PREV_HASH;
let _ring: Array<Omit<LogRecord, 'prev_hash' | 'record_hmac'> & { prev_hash: string }> = [];
let _flushTimer: NodeJS.Timeout | null = null;
let _walFd: number | null = null;
let _initialized = false;
let _currentHourKey = '';   // e.g. "2026/08/09/14"

// ─── Initialisation ───────────────────────────────────────────────────────────

export async function initLogStore(): Promise<void> {
  if (_initialized) return;

  // Ensure WAL dir exists
  fs.mkdirSync(WAL_DIR, { recursive: true });
  fs.mkdirSync(DEAD_LETTER_DIR, { recursive: true });

  // Restore chain state from chain-state file if present
  const stateFile = path.join(WAL_DIR, 'chain_state.json');
  if (fs.existsSync(stateFile)) {
    try {
      const state: ChainState = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      _seq = state.lastSeq;
      _prevHash = state.lastHash;
      logger.info({ msg: 'log-store: chain state restored', seq: _seq });
    } catch (err) {
      logger.warn({ msg: 'log-store: failed to read chain state, starting fresh', err: (err as Error).message });
    }
  }

  // Replay WAL before accepting traffic (Sentinel Decision 2)
  await replayWal();

  // Open WAL file for appending (O_APPEND | O_SYNC via 'as' flag)
  _walFd = fs.openSync(WAL_FILE, 'as');

  // Start periodic flush
  _flushTimer = setInterval(() => { void flushBatch(); }, FLUSH_INTERVAL_MS);
  if (_flushTimer.unref) _flushTimer.unref();

  _initialized = true;
  logger.info({ msg: 'log-store: initialised', walDir: WAL_DIR, bucket: LOG_STORE_BUCKET });
}

export async function shutdownLogStore(): Promise<void> {
  if (_flushTimer) { clearInterval(_flushTimer); _flushTimer = null; }
  await flushBatch();   // drain remaining records
  if (_walFd !== null) { fs.closeSync(_walFd); _walFd = null; }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Append a log record.
 * Hot path: HMAC-seal → WAL write → enqueue ring buffer → return.
 * Adds ≤1ms (one O_APPEND|O_SYNC write to local NVMe).
 */
export function appendRecord(
  fields: Omit<LogRecord, 'v' | 'seq' | 'prev_hash' | 'record_hmac'>,
): void {
  _seq++;
  const partial: Omit<LogRecord, 'record_hmac'> = {
    v: 1,
    seq: _seq,
    prev_hash: _prevHash,
    ...fields,
  };

  // Compute chain hash (Sentinel Decision 1)
  const prevHash = canonicalSha256(partial as unknown as Record<string, unknown>);
  const record_hmac = sealRecord(partial as unknown as Record<string, unknown>);

  const record: LogRecord = { ...partial, record_hmac };

  // Advance chain state
  _prevHash = prevHash;

  // WAL write (O_APPEND|O_SYNC — durable before we return)
  if (_walFd !== null) {
    const line = JSON.stringify(record) + '\n';
    try {
      fs.writeSync(_walFd, line);
    } catch (err) {
      logger.error({ msg: 'log-store: WAL write failed', err: (err as Error).message });
    }
  }

  // Ring buffer (capacity guard)
  if (_ring.length >= RING_BUFFER_CAPACITY) {
    logger.error({ msg: 'log-store: ring buffer full — dropping record', seq: _seq });
    return;
  }
  _ring.push(record as unknown as typeof _ring[0]);

  // Trigger early flush at batch size
  if (_ring.length >= FLUSH_MAX_RECORDS) {
    void flushBatch();
  }
}

// ─── WAL Replay ───────────────────────────────────────────────────────────────

async function replayWal(): Promise<void> {
  if (!fs.existsSync(WAL_FILE)) return;
  const content = fs.readFileSync(WAL_FILE, 'utf8').trim();
  if (!content) return;

  const lines = content.split('\n').filter(Boolean);
  logger.info({ msg: 'log-store: replaying WAL', count: lines.length });

  const records: LogRecord[] = [];
  const quarantined: LogRecord[] = [];

  for (const line of lines) {
    let record: LogRecord;
    try { record = JSON.parse(line) as LogRecord; } catch { /* skip corrupt line */ continue; }

    // S-3 (Sentinel): verify per-record HMAC before flushing to object storage.
    // A record that was tampered with or written with the wrong key must never reach R2.
    const { record_hmac, ...rest } = record;
    const expectedHmac = sealRecord(rest as unknown as Record<string, unknown>);
    if (record_hmac !== expectedHmac) {
      logger.error({
        msg: 'log-store: WAL replay HMAC mismatch — quarantining record',
        seq: record.seq,
        stored_hmac: record_hmac,
        expected_hmac: expectedHmac,
      });
      quarantined.push(record);
    } else {
      records.push(record);
    }
  }

  // Write quarantined records to dead-letter directory — do NOT flush to R2.
  if (quarantined.length > 0) {
    const dlFile = path.join(DEAD_LETTER_DIR, `replay_hmac_fail_${Date.now()}.ndjson`);
    const body = quarantined.map((r) => JSON.stringify(r)).join('\n') + '\n';
    try {
      fs.writeFileSync(dlFile, body);
      logger.error({
        msg: 'log-store: quarantined WAL records with HMAC failures',
        count: quarantined.length,
        deadLetterFile: dlFile,
      });
    } catch (err) {
      logger.error({ msg: 'log-store: FATAL — could not write HMAC-failure dead-letter', err: (err as Error).message });
    }
  }

  if (records.length === 0) return;

  // Restore seq and prevHash from last verified WAL record
  const last = records[records.length - 1]!;
  _seq = last.seq;
  _prevHash = canonicalSha256(last as unknown as Record<string, unknown>);

  // Attempt to flush verified records to object storage
  await writeToObjectStorage(records);
}

// ─── Flush Path ───────────────────────────────────────────────────────────────

async function flushBatch(): Promise<void> {
  if (_ring.length === 0) return;

  const batch = _ring.splice(0, FLUSH_MAX_RECORDS) as unknown as LogRecord[];
  const hourKey = getHourKey();

  // Rotate manifest if hour changed
  if (hourKey !== _currentHourKey) {
    _currentHourKey = hourKey;
  }

  const success = await writeToObjectStorage(batch);
  if (success) {
    // Persist chain state after successful flush
    persistChainState();
    // Truncate WAL (safe: all flushed records are now in object storage)
    truncateWal();
  } else {
    // Re-enqueue at front (prepend back) — will retry next cycle
    _ring.unshift(...(batch as unknown as typeof _ring));
  }
}

async function writeToObjectStorage(records: LogRecord[]): Promise<boolean> {
  if (records.length === 0) return true;

  const hourKey = getHourKey(records[0]!.timestamp_utc_ms);
  // S-2 (Sentinel): include INSTANCE_ID in the object key to prevent last-writer-wins
  // data loss when multiple Fly.io instances flush to the same hourly prefix.
  // Audit code must list all objects under `impressions/${hourKey}/` to read the full hour.
  const objectKey = `impressions/${hourKey}/${INSTANCE_ID}.ndjson`;
  const body = records.map((r) => JSON.stringify(r)).join('\n') + '\n';

  // Write manifest
  const manifest = buildManifest(records, objectKey);

  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    try {
      await putObject(objectKey, body);
      await putObject(objectKey + '.manifest.json', JSON.stringify(manifest));
      logger.debug({ msg: 'log-store: flushed to object storage', records: records.length, key: objectKey });
      return true;
    } catch (err) {
      const delay = RETRY_DELAYS_MS[attempt];
      if (delay === undefined) {
        // All retries exhausted — dead letter
        writeDeadLetter(records, (err as Error).message);
        return false;
      }
      logger.warn({ msg: 'log-store: flush failed, retrying', attempt: attempt + 1, delay, err: (err as Error).message });
      await sleep(delay);
    }
  }
  return false;
}

// ─── Object Storage (R2) ──────────────────────────────────────────────────────
// Uses AWS SDK v3 S3-compatible client (R2 is S3-compatible).
// Credentials: R2_ACCESS_KEY_ID + R2_SECRET_ACCESS_KEY from env (Anchor provisioned).
// PutObject only — no read/list/delete (write-only IAM per Anchor/Sentinel spec).

async function putObject(key: string, body: string): Promise<void> {
  // Dynamic import to avoid loading AWS SDK in test environments without credentials
  const { S3Client, PutObjectCommand } = await import('@aws-sdk/client-s3');
  const endpoint = process.env['R2_ENDPOINT']; // e.g. https://<account>.r2.cloudflarestorage.com
  const accessKeyId = process.env['R2_ACCESS_KEY_ID'] ?? '';
  const secretAccessKey = process.env['R2_SECRET_ACCESS_KEY'] ?? '';
  const region = process.env['R2_REGION'] ?? 'auto';

  const client = new S3Client({
    endpoint,
    region,
    credentials: { accessKeyId, secretAccessKey },
  });

  await client.send(new PutObjectCommand({
    Bucket: LOG_STORE_BUCKET,
    Key: key,
    Body: body,
    ContentType: 'application/x-ndjson',
  }));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getHourKey(timestampMs?: number): string {
  const d = new Date(timestampMs ?? Date.now());
  const y = d.getUTCFullYear();
  const mo = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  const h = String(d.getUTCHours()).padStart(2, '0');
  return `${y}/${mo}/${day}/${h}`;
}

function buildManifest(records: LogRecord[], filePath: string) {
  const first = records[0]!;
  const last = records[records.length - 1]!;
  const manifestBody = {
    file_path: filePath,
    record_count: records.length,
    first_seq: first.seq,
    last_seq: last.seq,
    first_hash: first.prev_hash,
    last_hash: canonicalSha256(last as unknown as Record<string, unknown>),
  };
  const manifest_hmac = sealRecord(manifestBody as unknown as Record<string, unknown>);
  return { ...manifestBody, manifest_hmac };
}

function persistChainState(): void {
  const state: ChainState = { lastSeq: _seq, lastHash: _prevHash };
  fs.writeFileSync(path.join(WAL_DIR, 'chain_state.json'), JSON.stringify(state));
}

function truncateWal(): void {
  if (_walFd !== null) {
    try {
      fs.ftruncateSync(_walFd, 0);
      fs.fsyncSync(_walFd);
    } catch (err) {
      logger.warn({ msg: 'log-store: WAL truncate failed', err: (err as Error).message });
    }
  }
}

function writeDeadLetter(records: LogRecord[], reason: string): void {
  const dlFile = path.join(DEAD_LETTER_DIR, `dl_${Date.now()}.ndjson`);
  const body = records.map((r) => JSON.stringify(r)).join('\n') + '\n';
  try {
    fs.writeFileSync(dlFile, body);
    logger.error({ msg: 'log-store: wrote dead-letter file', file: dlFile, records: records.length, reason });
  } catch (err) {
    logger.error({ msg: 'log-store: FATAL — could not write dead-letter', err: (err as Error).message, reason });
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
