/**
 * Portal auth routes — publisher/advertiser self-service
 * Spec: AMBIENT_PROTOTYPE_SPECS.md R3 SPEC-1, SPEC-2
 *
 * POST /v1/portal/auth/signup
 * POST /v1/portal/auth/login
 * GET  /v1/portal/auth/me
 * POST /v1/portal/auth/logout
 * GET  /v1/portal/auth/verify-email
 * POST /v1/portal/auth/resend-verification
 */
import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { getPool } from '../../db/pool';
import { logger } from '../../lib/logger';
import {
  generateVerificationToken,
  hashVerificationToken,
  issuePortalJwt,
  setPortalCookie,
  clearPortalCookie,
  denylistJwt,
  getPortalCookieName,
  PortalJwtPayload,
} from '../../lib/portal-auth';
import { sendVerificationEmail } from '../../lib/email';
import { portalAuth } from '../../middleware/portal-auth-middleware';

export const portalAuthRouter = Router();

const BLOCKED_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
]);
function emailDomainBlocked(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase() ?? '';
  return BLOCKED_DOMAINS.has(domain);
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => (req.body?.email ?? req.ip ?? 'unknown').toLowerCase(),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'RATE_LIMITED', message: 'Too many login attempts — try again in 15 minutes' },
});

// POST /v1/portal/auth/signup
portalAuthRouter.post('/signup', async (req: Request, res: Response): Promise<void> => {
  const { full_name, email, company_name, password, role } = req.body ?? {};

  if (!full_name || !email || !company_name || !password || !role) {
    const errors: Record<string, string> = {};
    if (!full_name) errors['full_name'] = 'required';
    if (!email) errors['email'] = 'required';
    if (!company_name) errors['company_name'] = 'required';
    if (!password) errors['password'] = 'required';
    if (!role) errors['role'] = 'required';
    res.status(422).json({ error: 'VALIDATION_ERROR', errors });
    return;
  }

  const emailLower = (email as string).toLowerCase().trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLower)) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { email: 'invalid email format' } });
    return;
  }
  if (emailDomainBlocked(emailLower)) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { email: 'must be a business email address' } });
    return;
  }
  if ((password as string).length < 12) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { password: 'minimum 12 characters' } });
    return;
  }
  if (!['publisher', 'advertiser', 'both'].includes(role as string)) {
    res.status(422).json({ error: 'VALIDATION_ERROR', errors: { role: 'must be publisher | advertiser | both' } });
    return;
  }

  const pool = getPool();
  const existing = await pool.query('SELECT user_id FROM portal_users WHERE email = $1', [emailLower]);
  if (existing.rows.length > 0) {
    res.status(409).json({ error: 'CONFLICT', message: 'An account with this email already exists' });
    return;
  }

  const passwordHash = await bcrypt.hash(password as string, 12);
  const { raw: tokenRaw, hash: tokenHash } = generateVerificationToken();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userResult = await client.query(
      `INSERT INTO portal_users (email, full_name, company_name, password_hash, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING user_id, email, role, status`,
      [emailLower, full_name, company_name, passwordHash, role],
    );
    const user = userResult.rows[0];
    await client.query(
      `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [user.user_id, tokenHash, expiresAt],
    );
    await client.query('COMMIT');

    try {
      await sendVerificationEmail({ to: emailLower, fullName: full_name as string, token: tokenRaw });
    } catch (emailErr) {
      logger.error({ msg: 'Verification email failed after signup', err: (emailErr as Error).message });
    }

    logger.info({ msg: 'portal_user.signup', userId: user.user_id, role });
    res.status(201).json({ user_id: user.user_id, email: emailLower, role: user.role, status: user.status });
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error({ msg: 'signup transaction failed', err: (err as Error).message });
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Signup failed — please try again' });
  } finally {
    client.release();
  }
});

// POST /v1/portal/auth/login
portalAuthRouter.post('/login', loginLimiter, async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'email and password required' });
    return;
  }
  const emailLower = (email as string).toLowerCase().trim();
  const pool = getPool();
  const { rows } = await pool.query(
    `SELECT user_id, email, full_name, company_name, role, password_hash, verified, status
     FROM portal_users WHERE email = $1`,
    [emailLower],
  );
  const user = rows[0];

  if (!user || !(await bcrypt.compare(password as string, user.password_hash))) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid credentials' });
    return;
  }
  if (!user.verified) {
    res.status(403).json({ error: 'email_not_verified', message: 'Please verify your email before logging in' });
    return;
  }
  if (user.status === 'suspended') {
    res.status(403).json({ error: 'ACCOUNT_SUSPENDED', message: 'This account has been suspended' });
    return;
  }

  const token = issuePortalJwt({ sub: user.user_id, email: user.email, role: user.role });
  setPortalCookie(res, token);
  res.status(200).json({
    user_id: user.user_id,
    email: user.email,
    full_name: user.full_name,
    company_name: user.company_name,
    role: user.role,
  });
});

// GET /v1/portal/auth/me
portalAuthRouter.get('/me', portalAuth, async (req: Request, res: Response): Promise<void> => {
  const jwtUser: PortalJwtPayload = (req as any).portalUser;
  const pool = getPool();
  const { rows } = await pool.query(
    `SELECT user_id, email, full_name, company_name, role, verified FROM portal_users WHERE user_id = $1`,
    [jwtUser.sub],
  );
  if (!rows[0]) { res.status(401).json({ error: 'UNAUTHENTICATED', message: 'User not found' }); return; }
  res.json(rows[0]);
});

// POST /v1/portal/auth/logout
portalAuthRouter.post('/logout', portalAuth, async (req: Request, res: Response): Promise<void> => {
  const payload: PortalJwtPayload = (req as any).portalUser;
  await denylistJwt(payload.jti, payload.exp);
  clearPortalCookie(res);
  res.status(204).end();
});

// GET /v1/portal/auth/verify-email?token=<token>
portalAuthRouter.get('/verify-email', async (req: Request, res: Response): Promise<void> => {
  const { token } = req.query;
  if (!token || typeof token !== 'string') {
    res.status(302).setHeader('Location', '/verify-email?error=missing').end();
    return;
  }
  const tokenHash = hashVerificationToken(token);
  const pool = getPool();
  const { rows } = await pool.query(
    `SELECT t.token_id, t.user_id, t.expires_at, t.used_at
     FROM email_verification_tokens t WHERE t.token_hash = $1`,
    [tokenHash],
  );
  const record = rows[0];
  if (!record || record.used_at !== null) {
    res.status(302).setHeader('Location', '/verify-email?error=invalid').end();
    return;
  }
  if (new Date(record.expires_at) < new Date()) {
    res.status(302).setHeader('Location', '/verify-email?error=expired').end();
    return;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE email_verification_tokens SET used_at = NOW() WHERE token_id = $1`, [record.token_id]);
    await client.query(`UPDATE portal_users SET verified = TRUE, status = 'active', updated_at = NOW() WHERE user_id = $1`, [record.user_id]);
    await client.query('COMMIT');
    logger.info({ msg: 'email_verified', userId: record.user_id });
    res.status(302).setHeader('Location', '/login?verified=true').end();
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error({ msg: 'verify-email transaction failed', err: (err as Error).message });
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Verification failed' });
  } finally {
    client.release();
  }
});

// POST /v1/portal/auth/resend-verification — always 204 (anti-enumeration)
portalAuthRouter.post('/resend-verification', async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body ?? {};
  if (!email || typeof email !== 'string') { res.status(204).end(); return; }
  const emailLower = email.toLowerCase().trim();
  const pool = getPool();

  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const { rows: rateRows } = await pool.query(
    `SELECT COUNT(*) AS cnt FROM email_resend_log WHERE email = $1 AND sent_at > $2`,
    [emailLower, oneHourAgo],
  );
  if (parseInt(rateRows[0]?.cnt ?? '0', 10) >= 3) { res.status(204).end(); return; }

  const { rows } = await pool.query(
    `SELECT user_id, full_name FROM portal_users WHERE email = $1 AND verified = FALSE`, [emailLower],
  );
  const user = rows[0];
  if (!user) { res.status(204).end(); return; }

  const { raw: tokenRaw, hash: tokenHash } = generateVerificationToken();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE email_verification_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, [user.user_id]);
    await client.query(`INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`, [user.user_id, tokenHash, expiresAt]);
    await client.query(`INSERT INTO email_resend_log (email) VALUES ($1)`, [emailLower]);
    await client.query('COMMIT');
    try { await sendVerificationEmail({ to: emailLower, fullName: user.full_name, token: tokenRaw }); }
    catch (e) { logger.error({ msg: 'Resend email failed', err: (e as Error).message }); }
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error({ msg: 'resend-verification failed', err: (err as Error).message });
  } finally {
    client.release();
  }
  res.status(204).end();
});
