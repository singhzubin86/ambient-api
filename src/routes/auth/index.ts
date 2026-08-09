/**
 * Auth routes
 *  POST /v1/auth/login        — advertiser email+password → JWT
 *  POST /v1/auth/refresh      — refresh JWT (same payload, new exp)
 *  POST /v1/publishers/:id/rotate-key — rotate publisher API key
 */
import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { getPool } from '../../db/pool';
import { config } from '../../lib/config';
import { advertiserJwtAuth } from '../../middleware/auth';
import { JwtPayload, LoginRequest, LoginResponse } from '../../types';

export const authRouter = Router();

// POST /v1/auth/login
authRouter.post('/login', async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body as LoginRequest;
  if (!email || !password) {
    res.status(400).json({ error: 'INVALID_REQUEST', message: 'email and password required' });
    return;
  }

  const pool = getPool();
  const { rows } = await pool.query(
    'SELECT user_id, advertiser_id, password_hash, role FROM advertiser_users WHERE email = $1',
    [email.toLowerCase().trim()],
  );
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid credentials' });
    return;
  }

  const payload: Omit<JwtPayload, 'iat' | 'exp'> = {
    sub: user.user_id,
    role: user.role,
    advertiser_id: user.advertiser_id,
  };
  const token = jwt.sign(payload, config.auth.jwtSecret, { expiresIn: config.auth.jwtExpiresIn });
  const response: LoginResponse = { token, expires_in: config.auth.jwtExpiresIn, role: user.role };
  res.json(response);
});

// POST /v1/auth/refresh
authRouter.post('/refresh', advertiserJwtAuth, (req: Request, res: Response): void => {
  const old = (req as any).jwtPayload as JwtPayload;
  const payload: Omit<JwtPayload, 'iat' | 'exp'> = {
    sub: old.sub,
    role: old.role,
    advertiser_id: old.advertiser_id,
  };
  const token = jwt.sign(payload, config.auth.jwtSecret, { expiresIn: config.auth.jwtExpiresIn });
  res.json({ token, expires_in: config.auth.jwtExpiresIn, role: old.role });
});
