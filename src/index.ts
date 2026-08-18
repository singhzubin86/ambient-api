/**
 * Ambient API — Entry Point
 */
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { config } from './lib/config';
import { logger } from './lib/logger';
import { getPool, closePool } from './db/pool';
import { getRedis, closeRedis } from './db/redis';
import { initLogStore, shutdownLogStore } from './services/log-store';
import { loadCampaigns, startCampaignCacheRefresh, stopCampaignCacheRefresh } from './services/campaign-cache';
import { startAnomalyMonitor, stopAnomalyMonitor } from './services/anomaly-monitor';

import { adsRequestRouter } from './routes/ads/request';
import { adsClickRouter } from './routes/ads/click';
import { authRouter } from './routes/auth';
import { campaignsRouter } from './routes/campaigns';
import { publishersRouter } from './routes/publishers';
import { reportingRouter } from './routes/reporting';
import { portalAuthRouter } from './routes/portal/auth';
import { portalPublishersRouter } from './routes/portal/publishers';
import { portalReportingRouter } from './routes/portal/reporting';

export async function createApp(): Promise<express.Application> {
  const app = express();

  // ── Security headers ────────────────────────────────────────────────────────
  app.use(helmet());

  // ── Body parsing ────────────────────────────────────────────────────────────
  app.use(express.json({ limit: '64kb' }));

  // ── Cookie parsing (required for portal HttpOnly JWT cookie) ────────────────
  app.use(cookieParser());

  // ── Rate limiting (per publisher_id enforced in middleware; global guard here)
  app.use('/v1/ads', rateLimit({
    windowMs: 60_000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'RATE_LIMITED', message: 'Too many requests' },
  }));

  // ── Routes ─────────────────────────────────────────────────────────────────
  // Ad hot path
  app.use('/v1/ads', adsRequestRouter);
  app.use('/v1/ads', adsClickRouter);

  // Admin routes (Bearer JWT, admin-only)
  app.use('/v1/auth', authRouter);
  app.use('/v1/campaigns', campaignsRouter);
  app.use('/v1/publishers', publishersRouter);
  app.use('/v1/reporting', reportingRouter);

  // Portal routes (HttpOnly cookie JWT, self-service)
  // All portal routes are namespaced under /v1/portal/ to avoid collision with admin routes.
  app.use('/v1/portal/auth', portalAuthRouter);
  app.use('/v1/portal/publishers', portalPublishersRouter);
  // Reporting sub-routes are also on the publishers router (mounted together below)
  app.use('/v1/portal/publishers', portalReportingRouter);

  // ── Health ─────────────────────────────────────────────────────────────────
  app.get('/v1/ads/health', (_req, res) => res.json({ status: 'ok', ts: Date.now() }));

  // ── 404 ────────────────────────────────────────────────────────────────────
  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found' }));

  // ── Error handler ──────────────────────────────────────────────────────────
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    logger.error({ msg: 'unhandled error', err: err.message, stack: err.stack });
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'An unexpected error occurred' });
  });

  return app;
}

async function main(): Promise<void> {
  logger.info({ msg: 'Ambient API starting', env: config.env });

  // ── Init log store (WAL replay before accepting traffic) ─────────────────
  await initLogStore();

  // ── Load campaign cache ───────────────────────────────────────────────────
  try {
    await loadCampaigns();
  } catch (err) {
    logger.warn({ msg: 'Initial campaign cache load failed (DB may not be up yet)', err: (err as Error).message });
  }
  startCampaignCacheRefresh();

  // ── Start anomaly monitor ─────────────────────────────────────────────────
  startAnomalyMonitor();

  const app = await createApp();
  const server = app.listen(config.port, () => {
    logger.info({ msg: `Ambient API listening on port ${config.port}` });
  });

  // ── Graceful shutdown ─────────────────────────────────────────────────────
  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ msg: `${signal} received — shutting down` });
    server.close(async () => {
      stopCampaignCacheRefresh();
      stopAnomalyMonitor();
      await shutdownLogStore();
      await closePool();
      await closeRedis();
      logger.info({ msg: 'Shutdown complete' });
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

// Only run main() when executed directly — not when imported by tests
if (require.main === module) {
  main().catch((err) => {
    logger.error({ msg: 'Fatal startup error', err: (err as Error).message });
    process.exit(1);
  });
}
