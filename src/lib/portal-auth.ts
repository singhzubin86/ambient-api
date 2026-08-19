/**
 * Portal auth helpers — token generation, JWT cookies, denylist
 * Spec: AMBIENT_PROTOTYPE_SPECS.md R3 SPEC-1, SPEC-2
 */
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { Response } from 'express';
import { getRedis } from '../db/redis';
import { logger } from './logger';

const JWT_SECRET = process.env['JWT_SECRET'] ?? 'dev-jwt-secret-change-in-production-32c';
const VERIFICATION_SECRET = process.env['VERIFICATION_TOKEN_SECRET'] ?? 'dev-verify-secret-change-in-production';

// ── Verification token ────────────────────────────────────────────────────────

/**
 * Generate a 32-byte CSPRNG verification token (raw) and its HMAC-SHA256 hash
 * for DB storage. The raw token goes in the email link; the hash is stored.
 * Spec: SPEC-2 — "32 bytes CSPRNG → base64url, stored as HMAC-SHA256"
 */
export function generateVerificationToken(): { raw: string; hash: string } {
  const raw = crypto.randomBytes(32).toString('base64url');
  const hash = crypto.createHmac('sha256', VERIFICATION_SECRET).update(raw).digest('hex');
  return { raw, hash };
}

export function hashVerificationToken(raw: string): string {
  return crypto.createHmac('sha256', VERIFICATION_SECRET).update(raw).digest('hex');
}

// ── Portal JWT (HttpOnly cookie) ──────────────────────────────────────────────

export interface PortalJwtPayload {
  sub: string;          // user_id
  email: string;
  role: 'publisher' | 'advertiser' | 'both';
  jti: string;          // for denylist on logout
  iat: number;
  exp: number;
}

const JWT_TTL_SECONDS = 24 * 60 * 60; // 24h per SPEC-1 R3 (Blueprint decision)
const COOKIE_NAME = '__Host-amb-portal';

export function issuePortalJwt(payload: Omit<PortalJwtPayload, 'jti' | 'iat' | 'exp'>): string {
  const jti = crypto.randomBytes(16).toString('hex');
  return jwt.sign({ ...payload, jti }, JWT_SECRET, { expiresIn: JWT_TTL_SECONDS });
}

export function verifyPortalJwt(token: string): PortalJwtPayload {
  return jwt.verify(token, JWT_SECRET) as PortalJwtPayload;
}

export function setPortalCookie(res: Response, token: string): void {
  // SameSite=None + Secure required for cross-origin cookie: API is on
  // ambient-api.fly.dev but the portal (and its middleware) runs on
  // ambient-portal.fly.dev. With SameSite=Lax the browser blocks the
  // cookie on cross-origin requests even with credentials:include.
  const isProd = process.env['NODE_ENV'] === 'production';
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: JWT_TTL_SECONDS * 1000,
    path: '/',
  });
}

export function clearPortalCookie(res: Response): void {
  const isProd = process.env['NODE_ENV'] === 'production';
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax', path: '/' });
}

export function getPortalCookieName(): string {
  return COOKIE_NAME;
}

// ── JWT denylist (Redis) ──────────────────────────────────────────────────────
// Spec: SPEC-1 R3 — "Redis denylist keyed by jti, TTL = remaining token expiry"

export async function denylistJwt(jti: string, expiresAt: number): Promise<void> {
  const ttlSeconds = Math.max(1, expiresAt - Math.floor(Date.now() / 1000));
  try {
    const redis = getRedis();
    await redis.set(`jwt_deny:${jti}`, '1', 'EX', ttlSeconds);
  } catch (err) {
    // Log but don't throw — logout should still succeed even if Redis is down.
    // The 24h expiry is a safety net in that case.
    logger.error({ msg: 'JWT denylist write failed', err: (err as Error).message, jti });
  }
}

export async function isJwtDenylisted(jti: string): Promise<boolean> {
  try {
    const redis = getRedis();
    const val = await redis.get(`jwt_deny:${jti}`);
    return val !== null;
  } catch (err) {
    logger.error({ msg: 'JWT denylist check failed', err: (err as Error).message, jti });
    return false; // fail open on Redis error — token still subject to 24h expiry
  }
}

// ── API key generation (SPEC-3) ───────────────────────────────────────────────
// base58-encoded for readability; same security as base64url at 32 bytes

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function bytesToBase58(bytes: Buffer): string {
  let num = BigInt('0x' + bytes.toString('hex'));
  let result = '';
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % 58n)]! + result;
    num = num / 58n;
  }
  // Leading zero bytes → leading '1' chars
  for (const byte of bytes) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result;
}

const API_KEY_PREFIX_LIVE = 'amb_live_';
const API_KEY_PREFIX_TEST = 'amb_test_';

export function generatePublisherApiKey(test = false): { apiKey: string; keyHash: string } {
  const prefix = test ? API_KEY_PREFIX_TEST : API_KEY_PREFIX_LIVE;
  const entropy = crypto.randomBytes(32);
  const suffix = bytesToBase58(entropy);
  const apiKey = prefix + suffix;
  // Store HMAC-SHA256, NOT bcrypt (keys are high-entropy, HMAC is correct — Blueprint decision)
  const keyHash = crypto.createHmac('sha256', JWT_SECRET).update(apiKey).digest('hex');
  return { apiKey, keyHash };
}

export function hashApiKey(apiKey: string): string {
  return crypto.createHmac('sha256', JWT_SECRET).update(apiKey).digest('hex');
}

export function maskApiKey(fullOrPrefix: string): string {
  // Show last 4 chars: amb_live_••••••••••••j3i2
  const prefix = fullOrPrefix.startsWith(API_KEY_PREFIX_LIVE)
    ? API_KEY_PREFIX_LIVE
    : API_KEY_PREFIX_TEST;
  const last4 = fullOrPrefix.slice(-4);
  return `${prefix}${'•'.repeat(12)}${last4}`;
}
