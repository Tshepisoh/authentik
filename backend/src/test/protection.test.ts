import { describe, expect, it } from 'vitest';
import request from 'supertest';
import type { DomainAnalysis, NotificationAnalysis, ThreatEntry, ThreatListUpdate } from '@authentik/shared';
import { testConfig } from '../config.js';
import { TtlCache } from '../lib/ttl-cache.js';
import type { Clock } from '../lib/ids.js';
import { EntityRegistry } from '../modules/merchant-verification/registry.js';
import {
  LocalBlocklistProvider,
  parseFeed,
  ReputationService,
  ThreatFeedProvider,
  type ReputationProvider,
  type ReputationResult,
} from '../modules/reputation/index.js';
import { ThreatListService } from '../modules/threat-intel/service.js';
import { as, clean, fakeFetcher, fakeReputation, harness, silentLog } from './harness.js';

const listed: ReputationResult = { status: 'completed', matches: [{ threatType: 'SOCIAL_ENGINEERING' }] };

function mutableClock(start = Date.parse('2026-10-24T00:00:00Z')): Clock & { advance(ms: number): void } {
  let t = start;
  return { now: () => new Date(t), advance: (ms) => void (t += ms) };
}

function countingProvider(result: ReputationResult, cacheTtlSeconds?: number): ReputationProvider & { calls: number } {
  const p = { id: 'counting', label: 'Counting', critical: true, cacheTtlSeconds, calls: 0, async check() { p.calls++; return result; } };
  return p;
}

const notification = (over: Record<string, unknown> = {}) => ({
  packageName: 'com.google.android.apps.messaging',
  findingCodes: [],
  linkHosts: [],
  localRulesVersion: 'android-2026.10.1',
  ...over,
});

describe('POST /v1/domains/analyze', () => {
  it('checks a bare hostname without visiting it, and stores nothing', async () => {
    const fetcher = fakeFetcher();
    const { app } = harness({ fetcher });
    const res = await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: 'takealot.com', source: 'notification' }).expect(200);
    const body = res.body as DomainAnalysis;
    expect(body.depth).toBe('quick');
    expect(body.target.hostname).toBe('takealot.com');
    expect(body.assessment.verdict).toBe('no_obvious_warnings');
    expect(body.assessment.checks).toContainEqual(expect.objectContaining({ check: 'page_evidence', status: 'skipped', detail: 'quick check' }));
    expect(fetcher.calls).toHaveLength(0);
    const reports = await request(app).get('/v1/reports').set(as('u1')).expect(200);
    expect(reports.body).toHaveLength(0);
  });

  it('fetches the page only for a full check', async () => {
    const fetcher = fakeFetcher();
    const { app } = harness({ fetcher });
    await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: 'https://shop.example.com/x', depth: 'full' }).expect(200);
    expect(fetcher.calls.map((u) => u.hostname)).toEqual(['shop.example.com']);
  });

  it('flags a look-alike bank domain', async () => {
    const { app } = harness();
    const res = await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: 'absa-secure-login.com' }).expect(200);
    expect(res.body.assessment.verdict).not.toBe('no_obvious_warnings');
    expect(res.body.assessment.findings.map((f: { code: string }) => f.code).join(',')).toMatch(/brand|lookalike/);
  });

  it('returns a reputation match as high risk', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation(listed)] });
    const res = await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: 'bad.example.net' }).expect(200);
    expect(res.body.assessment.verdict).toBe('high_risk');
  });

  it('blocks private addresses without fetching', async () => {
    const fetcher = fakeFetcher();
    const { app } = harness({ fetcher });
    const res = await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: '169.254.169.254', depth: 'full' }).expect(200);
    expect(res.body.assessment.verdict).toBe('blocked');
    expect(fetcher.calls).toHaveLength(0);
  });

  it('is inconclusive when reputation is unavailable', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation({ status: 'unavailable', detail: 'down' })] });
    const res = await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: 'example.org' }).expect(200);
    expect(res.body.assessment.verdict).toBe('inconclusive');
  });

  it('validates the body', async () => {
    const { app } = harness();
    await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: '' }).expect(400);
    await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: 'example.com', depth: 'deep' }).expect(400);
    await request(app).post('/v1/domains/analyze').set(as('u1')).send({ target: 'example.com', save: true }).expect(400);
    await request(app).post('/v1/domains/analyze').send({ target: 'example.com' }).expect(401);
  });
});

describe('POST /v1/notifications/analyze', () => {
  it('weighs the phone’s codes with server-owned severities', async () => {
    const { app } = harness();
    const res = await request(app)
      .post('/v1/notifications/analyze')
      .set(as('u1'))
      .send(notification({ findingCodes: ['payment_claim', 'payment_claim_release', 'made_up_code'] }))
      .expect(200);
    const body = res.body as NotificationAnalysis;
    expect(body.assessment.verdict).toBe('high_risk');
    expect(body.assessment.findings.map((f) => f.code).sort()).toEqual(['payment_claim', 'payment_claim_release']);
    expect(body.assessment.findings.every((f) => f.source === 'notification')).toBe(true);
    expect(body.assessment.headline).toMatch(/scam/);
  });

  it('checks each link and correlates the result into one assessment', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation((u) => (u.hostname === 'pay-release.top' ? listed : clean))] });
    const res = await request(app)
      .post('/v1/notifications/analyze')
      .set(as('u1'))
      .send(notification({ findingCodes: ['payment_claim'], linkHosts: ['pay-release.top', 'takealot.com'] }))
      .expect(200);
    const body = res.body as NotificationAnalysis;
    expect(body.links.map((l) => [l.target.hostname, l.assessment.verdict])).toEqual([
      ['pay-release.top', 'high_risk'],
      ['takealot.com', 'no_obvious_warnings'],
    ]);
    expect(body.assessment.verdict).toBe('high_risk');
    expect(body.assessment.findings.map((f) => f.code)).toContain('reputation_match');
  });

  it('ignores the phone’s own link codes so the same evidence isn’t counted twice', async () => {
    const { app } = harness();
    const res = await request(app)
      .post('/v1/notifications/analyze')
      .set(as('u1'))
      .send(notification({ findingCodes: ['lookalike_link', 'ip_link', 'known_threat_link'], linkHosts: ['example.org'] }))
      .expect(200);
    expect(res.body.assessment.findings.filter((f: { source: string }) => f.source === 'notification')).toHaveLength(0);
  });

  it('turns a private-address link into a warning, not a blocked notification', async () => {
    const { app } = harness();
    const res = await request(app).post('/v1/notifications/analyze').set(as('u1')).send(notification({ linkHosts: ['10.0.0.5'] })).expect(200);
    expect(res.body.assessment.verdict).toBe('suspicious');
    expect(res.body.assessment.findings.map((f: { code: string }) => f.code)).toContain('link_not_public');
  });

  it('stays inconclusive when the link couldn’t be checked', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation({ status: 'failed', detail: 'timeout' })] });
    const res = await request(app).post('/v1/notifications/analyze').set(as('u1')).send(notification({ linkHosts: ['example.org'] })).expect(200);
    expect(res.body.assessment.verdict).toBe('inconclusive');
  });

  it('refuses notification text and malformed input', async () => {
    const { app } = harness();
    await request(app).post('/v1/notifications/analyze').set(as('u1')).send(notification({ text: 'You have received R4,500' })).expect(400);
    await request(app).post('/v1/notifications/analyze').set(as('u1')).send(notification({ packageName: 'not a package' })).expect(400);
    await request(app).post('/v1/notifications/analyze').set(as('u1')).send(notification({ linkHosts: ['https://a.example.com/x'] })).expect(400);
    await request(app)
      .post('/v1/notifications/analyze')
      .set(as('u1'))
      .send(notification({ linkHosts: ['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com'] }))
      .expect(400);
  });

  it('stores nothing', async () => {
    const { app } = harness();
    await request(app).post('/v1/notifications/analyze').set(as('u1')).send(notification({ findingCodes: ['credential_request'] })).expect(200);
    const alerts = await request(app).get('/v1/alerts').set(as('u1')).expect(200);
    expect(alerts.body).toHaveLength(0);
    const reports = await request(app).get('/v1/reports').set(as('u1')).expect(200);
    expect(reports.body).toHaveLength(0);
  });
});

describe('GET /v1/threats/updates', () => {
  it('sends the full list first, then nothing when the phone is current', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation(clean), new LocalBlocklistProvider(['bad-shop.example'])] });
    const first = await request(app).get('/v1/threats/updates').set(as('u1')).expect(200);
    const update = first.body as ThreatListUpdate;
    expect(update.full).toBe(true);
    expect(update.added).toContainEqual({ domain: 'bad-shop.example', threatType: 'KNOWN_FRAUD' });
    expect(update.maxAgeSeconds).toBe(259_200);
    const fnb = update.brands.find((b) => b.name === 'FNB')!;
    expect(fnb).toMatchObject({ isBank: true, domains: ['fnb.co.za', 'firstrand.co.za'] });
    expect(fnb.mentions).toEqual(['fnb', 'first national bank']);

    const again = await request(app).get(`/v1/threats/updates?since=${update.version}`).set(as('u1')).expect(200);
    expect(again.body).toMatchObject({ version: update.version, full: false, added: [], removed: [] });
  });

  it('sends the full list for an unknown version and rejects a malformed one', async () => {
    const { app } = harness();
    const res = await request(app).get('/v1/threats/updates?since=0123456789abcdef').set(as('u1')).expect(200);
    expect(res.body.full).toBe(true);
    await request(app).get('/v1/threats/updates?since=../../etc').set(as('u1')).expect(400);
  });
});

describe('ThreatListService deltas', () => {
  it('sends only what changed since a recent version', () => {
    let entries: ThreatEntry[] = [{ domain: 'a.example', threatType: 'KNOWN_FRAUD' }, { domain: 'b.example', threatType: 'KNOWN_FRAUD' }];
    const clock = mutableClock();
    const svc = new ThreatListService({
      sources: [{ id: 'test', entries: () => entries }],
      registry: new EntityRegistry([]),
      config: testConfig(),
      clock,
    });
    const v1 = svc.update();
    entries = [{ domain: 'b.example', threatType: 'KNOWN_FRAUD' }, { domain: 'c.example', threatType: 'FEED_LISTED' }];
    // Rebuilt at most once a minute.
    expect(svc.update(v1.version).full).toBe(false);
    expect(svc.update(v1.version).added).toEqual([]);
    clock.advance(61_000);
    const v2 = svc.update(v1.version);
    expect(v2.version).not.toBe(v1.version);
    expect(v2).toMatchObject({ full: false, added: [{ domain: 'c.example', threatType: 'FEED_LISTED' }], removed: ['a.example'] });
  });

  it('caps the list and lets the curated blocklist win over feeds', () => {
    const svc = new ThreatListService({
      sources: [
        { id: 'curated', entries: () => [{ domain: 'x.example', threatType: 'KNOWN_FRAUD' }] },
        { id: 'feed', entries: () => [{ domain: 'x.example', threatType: 'FEED_LISTED' }, { domain: 'y.example', threatType: 'FEED_LISTED' }] },
      ],
      registry: new EntityRegistry([]),
      config: testConfig({ THREAT_LIST_MAX_ENTRIES: '1' }),
      clock: mutableClock(),
    });
    expect(svc.update().added).toEqual([{ domain: 'x.example', threatType: 'KNOWN_FRAUD' }]);
  });
});

describe('threat feeds', () => {
  it('parses domain, URL and hosts-file lines, and drops junk and private names', () => {
    const text = [
      '# comment',
      'bad.example',
      'https://phish.example.net/login?x=1',
      '0.0.0.0 malware.example.org',
      '127.0.0.1 localhost',
      '203.0.113.9',
      'router.local',
      'not a domain at all',
      '',
    ].join('\n');
    expect(parseFeed(text)).toEqual(['bad.example', 'phish.example.net', 'malware.example.org']);
  });

  it('is unavailable until loaded, matches subdomains, and keeps the last good set when feeds fail', async () => {
    let body: string | Error = 'phish.example.net\n';
    const feed = new ThreatFeedProvider(['https://feeds.example/list.txt'], silentLog, {
      fetchText: async () => {
        if (body instanceof Error) throw body;
        return body;
      },
    });
    expect((await feed.check(new URL('https://phish.example.net/'))).status).toBe('unavailable');
    await feed.refresh();
    expect(await feed.check(new URL('https://login.phish.example.net/'))).toEqual({ status: 'completed', matches: [{ threatType: 'FEED_LISTED' }] });
    expect(await feed.check(new URL('https://example.net/'))).toEqual({ status: 'completed', matches: [] });
    body = new Error('down');
    await feed.refresh();
    expect(feed.entries()).toEqual([{ domain: 'phish.example.net', threatType: 'FEED_LISTED' }]);
  });
});

describe('reputation cache', () => {
  it('reuses completed answers for the same host and path, until they expire', async () => {
    const clock = mutableClock();
    const p = countingProvider(clean, 60);
    const svc = new ReputationService([p], clock);
    await svc.check(new URL('https://a.example/x?q=1'));
    await svc.check(new URL('https://a.example/x?q=2'));
    expect(p.calls).toBe(1);
    await svc.check(new URL('https://a.example/y'));
    expect(p.calls).toBe(2);
    clock.advance(61_000);
    await svc.check(new URL('https://a.example/x'));
    expect(p.calls).toBe(3);
  });

  it('never caches failures, or providers without a TTL', async () => {
    const failing = countingProvider({ status: 'failed', detail: 'x' }, 60);
    const local = countingProvider(clean);
    const svc = new ReputationService([failing, local], mutableClock());
    await svc.check(new URL('https://a.example/'));
    await svc.check(new URL('https://a.example/'));
    expect(failing.calls).toBe(2);
    expect(local.calls).toBe(2);
  });

  it('TtlCache evicts the oldest entry past its cap', () => {
    const cache = new TtlCache<number>(mutableClock(), 2);
    cache.set('a', 1, 60);
    cache.set('b', 2, 60);
    cache.set('c', 3, 60);
    expect([cache.get('a'), cache.get('b'), cache.get('c')]).toEqual([undefined, 2, 3]);
  });
});
