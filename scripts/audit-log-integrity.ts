#!/usr/bin/env ts-node
/**
 * Sentinel Security Audit — §3.4 Tamper-Evidence Verification
 *
 * Independently verifies the tamper-evident log chain:
 *   1. Re-derives each record's HMAC seal (record_hmac) using LOG_SIGNING_KEY
 *   2. Re-derives each record's prev_hash and verifies chain continuity
 *   3. Verifies sequence numbers are gapless and monotonically increasing
 *   4. Verifies file-level manifest (if present)
 *   5. Reports any tampered, missing, or reordered records
 *
 * This script is intentionally INDEPENDENT of application code — it reimplements
 * the crypto primitives from scratch to provide genuine independent auditability.
 * Do not refactor it to import from src/lib/crypto.ts.
 *
 * Usage:
 *   LOG_SIGNING_KEY=<key> ts-node scripts/audit-log-integrity.ts <ndjson-file-or-dir>
 *   LOG_SIGNING_KEY=<key> ts-node scripts/audit-log-integrity.ts <ndjson-file>  # single file
 *
 * Exit codes:
 *   0  — all records verified, chain intact (pass)
 *   1  — integrity failures found (fail — investigate before launch)
 *   2  — usage / file error / missing LOG_SIGNING_KEY
 *
 * Sentinel Security Decisions V1 Decision 1 + AMBIENT_BETA_VALIDATION_PROTOCOL.md §3.4
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';
import crypto from 'crypto';

// ── Sentinel Decision 1: canonical JSON + HMAC-SHA256 ────────────────────────
// Reimplemented independently of src/lib/crypto.ts for auditability.

const LOG_SIGNING_KEY = process.env['LOG_SIGNING_KEY'];

function sortKeys(val: unknown): unknown {
  if (Array.isArray(val)) return val.map(sortKeys);
  if (val !== null && typeof val === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(val as object).sort()) {
      sorted[k] = sortKeys((val as Record<string, unknown>)[k]);
    }
    return sorted;
  }
  return val;
}

function canonicalJson(obj: Record<string, unknown>): string {
  return JSON.stringify(sortKeys(obj));
}

function hmacSha256Hex(key: string, data: string): string {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest('hex');
}

function canonicalSha256(obj: Record<string, unknown>): string {
  return 'sha256:' + crypto.createHash('sha256').update(canonicalJson(obj), 'utf8').digest('hex');
}

function deriveExpectedHmac(record: Record<string, unknown>): string {
  const { record_hmac: _excluded, ...rest } = record;
  return 'hmac-sha256:' + hmacSha256Hex(LOG_SIGNING_KEY!, canonicalJson(rest));
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface LogRecord {
  v: number;
  seq: number;
  event_type: string;
  timestamp_utc_ms: number;
  publisher_id: string;
  prev_hash: string;
  record_hmac: string;
  [key: string]: unknown;
}

interface IntegrityFailure {
  lineNumber: number;
  file: string;
  seq: number | undefined;
  kind: 'hmac_mismatch' | 'chain_break' | 'seq_gap' | 'seq_duplicate' | 'missing_field' | 'parse_error';
  detail: string;
}

interface AuditResult {
  filesScanned: number;
  recordsVerified: number;
  failures: IntegrityFailure[];
}

const GENESIS_PREV_HASH = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';

// ── File verification ─────────────────────────────────────────────────────────

async function verifyNdjsonFile(
  filePath: string,
  result: AuditResult,
  expectedPrevHash?: string,
): Promise<string | null> {
  // Returns the hash of the last record in this file (for cross-file chain continuity).

  const stream = fs.createReadStream(filePath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  let lineNumber = 0;
  let lastHash: string | null = null;
  let prevHash: string = expectedPrevHash ?? GENESIS_PREV_HASH;
  let lastSeq: number | null = null;
  const seenSeqs = new Set<number>();

  for await (const line of rl) {
    lineNumber++;
    const trimmed = line.trim();
    if (!trimmed) continue;

    let record: Record<string, unknown>;
    try {
      record = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      result.failures.push({
        lineNumber,
        file: path.basename(filePath),
        seq: undefined,
        kind: 'parse_error',
        detail: 'JSON parse error — line is corrupt or not a valid record',
      });
      continue;
    }

    const r = record as LogRecord;

    // Required fields check
    const required = ['v', 'seq', 'event_type', 'timestamp_utc_ms', 'publisher_id', 'prev_hash', 'record_hmac'];
    const missing = required.filter((f) => !(f in record));
    if (missing.length > 0) {
      result.failures.push({
        lineNumber,
        file: path.basename(filePath),
        seq: r.seq,
        kind: 'missing_field',
        detail: `Missing required fields: ${missing.join(', ')}`,
      });
      continue;
    }

    // Sequence gap / duplicate check
    if (seenSeqs.has(r.seq)) {
      result.failures.push({
        lineNumber,
        file: path.basename(filePath),
        seq: r.seq,
        kind: 'seq_duplicate',
        detail: `Duplicate seq ${r.seq}`,
      });
    } else if (lastSeq !== null && r.seq !== lastSeq + 1) {
      result.failures.push({
        lineNumber,
        file: path.basename(filePath),
        seq: r.seq,
        kind: 'seq_gap',
        detail: `Expected seq ${lastSeq + 1}, got ${r.seq} — gap of ${r.seq - lastSeq - 1} records`,
      });
    }
    seenSeqs.add(r.seq);
    lastSeq = r.seq;

    // Chain continuity: verify prev_hash matches hash of prior record
    if (r.prev_hash !== prevHash) {
      result.failures.push({
        lineNumber,
        file: path.basename(filePath),
        seq: r.seq,
        kind: 'chain_break',
        detail: `prev_hash mismatch. Expected: ${prevHash.slice(0, 20)}... Got: ${String(r.prev_hash).slice(0, 20)}...`,
      });
    }

    // HMAC seal verification
    const expected = deriveExpectedHmac(record);
    if (r.record_hmac !== expected) {
      result.failures.push({
        lineNumber,
        file: path.basename(filePath),
        seq: r.seq,
        kind: 'hmac_mismatch',
        detail: `record_hmac mismatch. Stored: ${String(r.record_hmac).slice(0, 40)}... Expected: ${expected.slice(0, 40)}...`,
      });
    }

    // Advance chain state using canonical hash of this record
    // (same as canonicalSha256 in application code)
    const { record_hmac: _h, ...rest } = record;
    prevHash = canonicalSha256(rest as Record<string, unknown>);
    lastHash = prevHash;
    result.recordsVerified++;
  }

  if (filePath !== '-') result.filesScanned++;
  return lastHash;
}

// ── Manifest verification ─────────────────────────────────────────────────────

function verifyManifest(manifestPath: string, result: AuditResult): void {
  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
  } catch {
    console.warn(`[WARN] Could not parse manifest: ${manifestPath}`);
    return;
  }

  const { manifest_hmac, ...rest } = manifest;
  const expectedHmac = 'hmac-sha256:' + hmacSha256Hex(LOG_SIGNING_KEY!, canonicalJson(rest as Record<string, unknown>));

  if (manifest_hmac !== expectedHmac) {
    result.failures.push({
      lineNumber: 0,
      file: path.basename(manifestPath),
      seq: undefined,
      kind: 'hmac_mismatch',
      detail: `Manifest HMAC mismatch — manifest may be tampered. Stored: ${String(manifest_hmac).slice(0, 40)}...`,
    });
  } else {
    console.log(`  ✅ Manifest OK: ${path.basename(manifestPath)}`);
  }
}

// ── Directory scan ────────────────────────────────────────────────────────────

async function auditPath(targetPath: string, result: AuditResult): Promise<void> {
  const stat = fs.statSync(targetPath);
  if (stat.isDirectory()) {
    // Sort files for deterministic processing order (hourly files)
    const entries = fs.readdirSync(targetPath).sort();

    for (const entry of entries) {
      const full = path.join(targetPath, entry);
      const s = fs.statSync(full);
      if (s.isDirectory()) {
        await auditPath(full, result);
      } else if (entry.endsWith('.manifest.json')) {
        verifyManifest(full, result);
      } else if (entry.endsWith('.ndjson') || entry.endsWith('.jsonl')) {
        console.log(`  Verifying: ${path.relative(targetPath, full)}`);
        await verifyNdjsonFile(full, result);
      }
    }
  } else {
    await verifyNdjsonFile(targetPath, result);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error('Usage: LOG_SIGNING_KEY=<key> ts-node scripts/audit-log-integrity.ts <ndjson-file-or-dir>\n');
    process.exit(2);
  }

  if (!LOG_SIGNING_KEY) {
    console.error('Error: LOG_SIGNING_KEY environment variable is required.\n');
    process.exit(2);
  }

  if (!fs.existsSync(target)) {
    console.error(`Error: path does not exist: ${target}`);
    process.exit(2);
  }

  const result: AuditResult = { filesScanned: 0, recordsVerified: 0, failures: [] };

  console.log('\n══ Sentinel Log Integrity Audit — §3.4 ══════════════════════════');
  console.log(`Target: ${target}\n`);

  await auditPath(target, result);

  console.log('\n── Results ──────────────────────────────────────────────────────');
  console.log(`Files scanned:    ${result.filesScanned}`);
  console.log(`Records verified: ${result.recordsVerified}`);
  console.log(`Failures:         ${result.failures.length}`);

  if (result.failures.length === 0) {
    console.log('\n✅ PASS — Chain intact, all HMAC seals verified. Log is tamper-evident.\n');
    process.exit(0);
  } else {
    console.log('\n🔴 FAIL — Integrity failures detected. Investigate before launch.\n');
    console.log('Failures:');
    for (const f of result.failures) {
      const seqStr = f.seq !== undefined ? `seq=${f.seq}` : 'seq=?';
      console.log(`  [${f.file}:L${f.lineNumber}] ${seqStr} kind=${f.kind}: ${f.detail}`);
    }
    console.log('');

    const kinds = result.failures.reduce<Record<string, number>>((acc, f) => {
      acc[f.kind] = (acc[f.kind] ?? 0) + 1;
      return acc;
    }, {});
    console.log('Summary by kind:', kinds);
    console.log('');

    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(2);
});
