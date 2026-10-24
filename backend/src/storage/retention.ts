import type { Logger } from 'pino';
import type { Store } from './types.js';
import type { Clock } from '../lib/ids.js';

/** Collections whose documents carry `expiresAt` and must be physically deleted when it passes. */
const EXPIRING = ['reports', 'alerts', 'sandboxSessions'] as const;

/** One pass of the retention sweep. Never throws: a failed sweep is retried on the next run. */
export async function sweepExpired(store: Store, clock: Clock, log: Logger): Promise<number> {
  let total = 0;
  for (const name of EXPIRING) {
    try {
      total += await store[name].purgeExpired(clock.now());
    } catch (err) {
      log.warn({ err, collection: name }, 'retention sweep failed');
    }
  }
  if (total) log.info({ deleted: total }, 'retention sweep');
  return total;
}

/**
 * Runs the sweep at startup and then on an interval. Reports are always hidden
 * once expired; this makes sure they are also deleted, so the retention
 * promise in the privacy statement holds without paid Firestore TTL policies.
 */
export function startRetentionSweeper(store: Store, clock: Clock, log: Logger, intervalMs = 60 * 60_000) {
  void sweepExpired(store, clock, log);
  const timer = setInterval(() => void sweepExpired(store, clock, log), intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
