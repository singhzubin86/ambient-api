import { Pool } from 'pg';
import { config } from '../lib/config';
import { logger } from '../lib/logger';

let _pool: Pool | null = null;

export function getPool(): Pool {
  if (!_pool) {
    _pool = new Pool({ connectionString: config.db.url });
    _pool.on('error', (err) => logger.error({ msg: 'pg pool error', err: err.message }));
  }
  return _pool;
}

export async function closePool(): Promise<void> {
  if (_pool) {
    await _pool.end();
    _pool = null;
  }
}
