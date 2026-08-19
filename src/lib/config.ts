import dotenv from 'dotenv';
dotenv.config();

function required(key: string): string {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required env var: ${key}`);
  return val;
}

function optional(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}

export const config = {
  env: optional('NODE_ENV', 'development'),
  port: parseInt(optional('PORT', '3000'), 10),

  db: {
    url: optional('DATABASE_URL', 'postgres://ambient:ambient@localhost:5432/ambient_dev'),
  },

  redis: {
    url: optional('REDIS_URL', 'redis://localhost:6379'),
  },

  auth: {
    jwtSecret: optional('JWT_SECRET', 'dev-jwt-secret-change-in-production-32c'),
    jwtExpiresIn: 3600 * 8, // 8 hours
    impressionTokenSecret: optional(
      'IMPRESSION_TOKEN_SECRET',
      'dev-imp-secret-change-in-production-32c',
    ),
    apiKeyPrefix: optional('API_KEY_PREFIX', 'amb_'),
  },

  logStore: {
    type: optional('LOG_STORE_TYPE', 'file') as 'file' | 's3' | 'gcs',
    path: optional('LOG_STORE_PATH', './logs/events'),
    bucket: process.env['LOG_STORE_BUCKET'],
  },

  campaign: {
    cacheTtlMs: parseInt(optional('CAMPAIGN_CACHE_TTL_MS', '30000'), 10),
  },

  freqCap: {
    ttlSeconds: 1800,   // Signal decision 1 — 30 min, locked
    hardCap: 2,          // Signal decision 1 — 2 impressions per session window
  },

  anomaly: {
    windowMinutes: 5,                      // Signal decision 4
    spikeMultiplier: 3.0,                  // Signal decision 4
    bootstrapDays: 7,                      // use absolute cap for days 0-6
    bootstrapAbsoluteCap: 100,             // Signal decision 4 — days 0-6 hard cap
    trailingDays: 7,                       // Signal decision 4 — 7-day median baseline
  },

  cors: {
    // Comma-separated list of allowed origins for browser-facing portal/API endpoints.
    // Always includes the production portal. Extend via ALLOWED_ORIGINS env var.
    allowedOrigins: optional(
      'ALLOWED_ORIGINS',
      'https://ambient-portal.fly.dev',
    ).split(',').map(o => o.trim()).filter(Boolean),
  },

  // Warden-required blocked/conditional categories — MUST NOT be overridden at runtime
  advertiserCategories: {
    blocked: [
      'pharma_rx',
      'investment_securities',
      'gambling',
      'cannabis',
      'political',
      'adult',
    ] as const,
    conditional: [
      'alcohol',
      'firearms',
      'financial_services',
      'healthcare_general',
    ] as const,
  },
} as const;
