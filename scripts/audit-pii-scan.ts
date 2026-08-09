#!/usr/bin/env ts-node
/**
 * Sentinel Security Audit — §3.1 PII Scan
 *
 * Reads NDJSON log files (from a local export directory or stdin) and scans
 * every field value for known PII patterns.  This is a hard gate: zero PII
 * findings are required before beta launch.
 *
 * Usage:
 *   ts-node scripts/audit-pii-scan.ts <path-to-ndjson-file-or-dir>
 *   cat exported.ndjson | ts-node scripts/audit-pii-scan.ts -
 *
 * Exit codes:
 *   0  — no PII found (pass)
 *   1  — PII found (fail — do NOT launch)
 *   2  — usage / file error
 *
 * Sentinel Security Decisions V1 §3.1 — AMBIENT_BETA_VALIDATION_PROTOCOL.md
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';

// ── PII patterns (mirrors crypto.ts PII_PATTERNS + field name checks) ─────────
const PII_REGEXES: Array<{ label: string; re: RegExp }> = [
  { label: 'email',        re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  { label: 'us-phone',     re: /\b\d{3}[.\-\s]?\d{3}[.\-\s]?\d{4}\b/ },
  { label: 'ssn',          re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { label: 'credit-card',  re: /\b(?:\d[ -]?){13,16}\b/ },
  { label: 'ipv4',         re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
  { label: 'ipv6',         re: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/ },
];

// Field names that must never appear in log records
const BANNED_FIELD_NAMES = new Set([
  'user_id', 'email', 'device_id', 'ip', 'ip_address', 'ipv4', 'ipv6',
  'phone', 'ssn', 'credit_card', 'name', 'first_name', 'last_name',
  'address', 'postal_code', 'zip',
]);

// Fields that are legitimately hashed and should not be scanned for raw PII
const HASHED_FIELDS = new Set(['user_agent_hash', 'record_hmac', 'prev_hash']);

// Fields that contain tokens/HMACs — skip PII regex scan (they're opaque)
const OPAQUE_FIELDS = new Set(['impression_token', 'record_hmac', 'prev_hash']);

interface Finding {
  lineNumber: number;
  file: string;
  field: string;
  pattern: string;
  excerpt: string;
}

interface ScanResult {
  filesScanned: number;
  recordsScanned: number;
  findings: Finding[];
}

// ── Recursive field scanner ───────────────────────────────────────────────────

function scanValue(
  val: unknown,
  fieldPath: string,
  lineNumber: number,
  file: string,
  findings: Finding[],
): void {
  if (val === null || val === undefined) return;

  if (typeof val === 'object' && !Array.isArray(val)) {
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      const childPath = fieldPath ? `${fieldPath}.${k}` : k;

      // Check for banned field names (any nesting depth)
      const leafKey = k.toLowerCase();
      if (BANNED_FIELD_NAMES.has(leafKey)) {
        findings.push({
          lineNumber,
          file,
          field: childPath,
          pattern: 'banned-field-name',
          excerpt: String(v).slice(0, 80),
        });
        // Still scan the value for patterns in case there are nested objects
      }

      scanValue(v, childPath, lineNumber, file, findings);
    }
    return;
  }

  if (Array.isArray(val)) {
    val.forEach((item, i) =>
      scanValue(item, `${fieldPath}[${i}]`, lineNumber, file, findings),
    );
    return;
  }

  // Leaf string value — skip opaque/hashed fields
  if (typeof val === 'string') {
    const leafField = fieldPath.split('.').pop() ?? fieldPath;
    if (OPAQUE_FIELDS.has(leafField) || HASHED_FIELDS.has(leafField)) return;

    for (const { label, re } of PII_REGEXES) {
      if (re.test(val)) {
        findings.push({
          lineNumber,
          file,
          field: fieldPath,
          pattern: label,
          excerpt: val.slice(0, 80),
        });
      }
    }
  }
}

// ── File scanning ─────────────────────────────────────────────────────────────

async function scanNdjsonFile(filePath: string, result: ScanResult): Promise<void> {
  const stream = filePath === '-'
    ? process.stdin
    : fs.createReadStream(filePath, { encoding: 'utf8' });

  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  let lineNumber = 0;

  for await (const line of rl) {
    lineNumber++;
    const trimmed = line.trim();
    if (!trimmed) continue;

    let record: unknown;
    try {
      record = JSON.parse(trimmed);
    } catch {
      console.error(`[WARN] ${filePath}:${lineNumber} — JSON parse error, skipping`);
      continue;
    }

    result.recordsScanned++;
    scanValue(record, '', lineNumber, filePath === '-' ? '<stdin>' : path.basename(filePath), result.findings);
  }

  if (filePath !== '-') result.filesScanned++;
}

async function scanPath(targetPath: string, result: ScanResult): Promise<void> {
  const stat = fs.statSync(targetPath);
  if (stat.isDirectory()) {
    const entries = fs.readdirSync(targetPath);
    for (const entry of entries) {
      const full = path.join(targetPath, entry);
      const s = fs.statSync(full);
      if (s.isDirectory()) {
        await scanPath(full, result);
      } else if (entry.endsWith('.ndjson') || entry.endsWith('.jsonl')) {
        await scanNdjsonFile(full, result);
      }
    }
  } else {
    await scanNdjsonFile(targetPath, result);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error('Usage: ts-node scripts/audit-pii-scan.ts <ndjson-file-or-dir|->\n');
    process.exit(2);
  }

  if (target !== '-' && !fs.existsSync(target)) {
    console.error(`Error: path does not exist: ${target}`);
    process.exit(2);
  }

  const result: ScanResult = { filesScanned: 0, recordsScanned: 0, findings: [] };

  if (target === '-') {
    await scanNdjsonFile('-', result);
  } else {
    await scanPath(target, result);
  }

  console.log('\n══ Sentinel PII Scan — §3.1 ══════════════════════════════════════');
  console.log(`Files scanned:   ${result.filesScanned}`);
  console.log(`Records scanned: ${result.recordsScanned}`);
  console.log(`Findings:        ${result.findings.length}`);

  if (result.findings.length === 0) {
    console.log('\n✅ PASS — No PII found. Safe for beta launch (PII gate).\n');
    process.exit(0);
  } else {
    console.log('\n🔴 FAIL — PII detected. DO NOT launch until resolved.\n');
    console.log('Findings:');
    for (const f of result.findings) {
      console.log(
        `  [${f.file}:L${f.lineNumber}] field="${f.field}" pattern="${f.pattern}" excerpt="${f.excerpt}"`,
      );
    }
    console.log('');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(2);
});
