import { AuthentikProtection, type ThreatListInfo } from '@modules/authentik-protection';
import { api } from '@/shared/api/client';

const SYNC_EVERY_MS = 6 * 60 * 60 * 1000;
let inFlight: Promise<ThreatListInfo | null> | null = null;

/**
 * Brings the phone's threat list up to date so the native listener can check
 * links offline. Throttled, so it's safe to call on every focus. Resolves to
 * null where the native module doesn't exist.
 */
export function syncThreatList({ force = false } = {}): Promise<ThreatListInfo | null> {
  const native = AuthentikProtection;
  if (!native) return Promise.resolve(null);
  const info = native.getThreatListInfo();
  if (!force && info.fresh && info.fetchedAt && Date.now() - info.fetchedAt < SYNC_EVERY_MS) return Promise.resolve(info);

  inFlight ??= (async () => {
    try {
      const update = await api.threatUpdates(info.version ?? undefined);
      try {
        return native.applyThreatUpdate(JSON.stringify(update));
      } catch (e) {
        // The stored list didn't match the delta's base version: start again from the full list.
        if ((e as { code?: string }).code !== 'ERR_THREAT_DELTA') throw e;
        return native.applyThreatUpdate(JSON.stringify(await api.threatUpdates()));
      }
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}
