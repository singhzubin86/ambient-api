/**
 * Portal auth middleware — validates HttpOnly cookie JWT for portal routes
 * Spec: AMBIENT_PROTOTYPE_SPECS.md R3 SPEC-1
 *
 * Returns 401 JSON (never redirect) — Canvas handles browser redirect.
 */
import { Request, Response, NextFunction } from 'express';
import { verifyPortalJwt, isJwtDenylisted, getPortalCookieName, PortalJwtPayload } from '../lib/portal-auth';
import { logger } from '../lib/logger';

export async function portalAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = req.cookies?.[getPortalCookieName()];
  if (!token) {
    res.status(401).json({ error: 'UNAUTHENTICATED', message: 'No session — please log in' });
    return;
  }
  try {
    const payload = verifyPortalJwt(token);
    // Check denylist (logout invalidation)
    if (await isJwtDenylisted(payload.jti)) {
      res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Session has been invalidated' });
      return;
    }
    (req as any).portalUser = payload;
    next();
  } catch (err) {
    logger.debug({ msg: 'Portal JWT invalid', err: (err as Error).message });
    res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Invalid or expired session' });
  }
}

/** Role guard — use after portalAuth */
export function requirePortalRole(...roles: ('publisher' | 'advertiser' | 'both')[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user: PortalJwtPayload = (req as any).portalUser;
    // 'both' role grants access to publisher AND advertiser routes
    const effectiveRoles: string[] = user.role === 'both'
      ? ['publisher', 'advertiser', 'both']
      : [user.role];
    const allowed = roles.some(r => effectiveRoles.includes(r));
    if (!allowed) {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient role for this resource' });
      return;
    }
    next();
  };
}
