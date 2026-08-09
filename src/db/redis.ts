import Redis from 'ioredis';
import { config } from '../lib/config';
import { logger } from '../lib/logger';

let _redis: Redis | null = null;

export function getRedis(): Redis {
  if (!_redis) {
    _redis = new Redis(config.redis.url, { lazyConnect: true, enableOfflineQueue: false });
    _redis.on('error', (err: Error) => logger.error({ msg: 'redis error', err: err.message }));
  }
  return _redis;
}

export async function closeRedis(): Promise<void> {
  if (_redis) {
    await _redis.quit();
    _redis = null;
  }
}
