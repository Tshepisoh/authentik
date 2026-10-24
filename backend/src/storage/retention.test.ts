import { describe, expect, it } from 'vitest';
import { createMemoryStore } from './memory.js';
import { sweepExpired } from './retention.js';
import { silentLog } from '../test/harness.js';

describe('retention sweep', () => {
  it('physically deletes expired documents and keeps live ones', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const clock = { now: () => now };
    const store = createMemoryStore(clock);
    const base = { uid: 'u', createdAt: now.toISOString(), reportId: 'r', code: 'c', title: 't', summary: 's', hostname: null, severity: 'high' as const, reviewedAt: null, dedupeKey: 'k' };
    await store.alerts.put({ ...base, id: 'old', expiresAt: '2026-01-02T00:00:00Z' });
    await store.alerts.put({ ...base, id: 'new', expiresAt: '2026-03-01T00:00:00Z' });
    await store.profiles.put({ id: 'u', uid: 'u', email: null, emailVerified: false, onboardingCompletedAt: null, createdAt: now.toISOString() });

    expect(await sweepExpired(store, clock, silentLog)).toBe(0);
    now = new Date('2026-02-01T00:00:00Z');
    expect(await sweepExpired(store, clock, silentLog)).toBe(1);
    expect((await store.alerts.listByUser('u')).map((a) => a.id)).toEqual(['new']);
    expect(await store.profiles.get('u')).not.toBeNull(); // collections without expiry are untouched
  });
});
