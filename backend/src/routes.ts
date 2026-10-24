import { Router } from 'express';
import { z } from 'zod';
import type { Deps } from './container.js';
import { parse } from './lib/validate.js';
import { requireRecentSignIn, uidOf } from './modules/auth/middleware.js';
import { toReport } from './modules/reports/service.js';
import { rateLimits } from './security/rate-limiting/index.js';
import { sha256 } from './lib/ids.js';

const urlBody = z.object({ url: z.string().min(1).max(2048) });
const idParam = z.object({ id: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/) });

const paymentBody = z.object({
  expected: z.object({
    merchant: z.string().trim().min(1).max(100),
    amountMinor: z.number().int().min(0).max(10_000_000_00),
    currency: z.string().regex(/^[A-Za-z]{3}$/),
    allowedAdjustmentMinor: z.number().int().min(0).max(1_000_000_00).optional(),
  }),
  observed: z
    .object({
      checkoutUrl: z.string().min(1).max(2048).optional(),
      redirectChain: z.array(z.string().max(2048)).max(10).optional(),
      recipientName: z.string().trim().min(1).max(200).optional(),
      amountMinor: z.number().int().min(0).max(10_000_000_00).optional(),
      currency: z.string().regex(/^[A-Za-z]{3}$/).optional(),
      extractionId: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/).optional(),
    })
    .refine((o) => o.checkoutUrl || o.extractionId, { message: 'checkoutUrl or extractionId is required' }),
});

const hostname = z.string().regex(/^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/i, 'a hostname such as example.com');

const domainBody = z.object({
  target: z.string().min(1).max(2048),
  source: z.enum(['manual', 'share', 'notification', 'dns']).optional(),
  depth: z.enum(['quick', 'full']).optional(),
}).strict();

const notificationBody = z.object({
  packageName: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/).max(255),
  findingCodes: z.array(z.string().regex(/^[a-z_]{1,64}$/)).max(20),
  linkHosts: z.array(hostname).max(5),
  localRulesVersion: z.string().regex(/^[A-Za-z0-9._-]{1,40}$/),
}).strict();

const extractBody = z.union([
  z.object({ checkoutUrl: z.string().min(1).max(2048) }).strict(),
  z.object({ sandboxSessionId: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/) }).strict(),
]);

/** All `/v1` routes. Everything here is behind `requireAuth`. */
export function apiRoutes(deps: Deps): Router {
  const r = Router();
  const { account, scans, payments, reports, alerts, settings, sandbox, store, clock, notificationAnalysis, threatList } = deps;

  // ── Account ──
  r.get('/me', async (req, res) => {
    res.json(await account.profile(req.auth!));
  });
  r.patch('/me', async (req, res) => {
    const body = parse(z.object({ onboardingCompleted: z.boolean().optional() }).strict(), req.body);
    res.json(await account.update(req.auth!, body));
  });
  r.post('/me/sessions/revoke', rateLimits.account(), async (req, res) => {
    await account.revokeSessions(uidOf(req));
    res.status(204).end();
  });
  r.delete('/me', rateLimits.account(), requireRecentSignIn(), async (req, res) => {
    await account.delete(uidOf(req));
    res.status(204).end();
  });

  // ── Website scans ──
  r.post('/scans', rateLimits.scans(), async (req, res) => {
    const { url } = parse(urlBody, req.body);
    res.status(201).json(toReport(await scans.scan(uidOf(req), url)));
  });

  // ── Android protection: domain checks, notification correlation, offline threat list ──
  r.post('/domains/analyze', rateLimits.domains(), async (req, res) => {
    const { target, ...opts } = parse(domainBody, req.body);
    res.json(await scans.analyzeDomain(uidOf(req), target, opts));
  });
  r.post('/notifications/analyze', rateLimits.notifications(), async (req, res) => {
    const body = parse(notificationBody, req.body);
    res.json(await notificationAnalysis.analyze(uidOf(req), body));
  });
  r.get('/threats/updates', rateLimits.threats(), (req, res) => {
    const { since } = parse(z.object({ since: z.string().regex(/^[a-f0-9]{16}$/).optional() }), req.query);
    res.set('cache-control', 'private, no-cache');
    res.json(threatList.update(since));
  });

  // ── Payment integrity ──
  // Reads the amount and recipient from a payment page, rendered in the isolated worker.
  r.post('/payment-checks/extract', rateLimits.paymentChecks(), async (req, res) => {
    const body = parse(extractBody, req.body);
    res.status(201).json(await deps.extractions.extract(uidOf(req), body));
  });
  r.post('/payment-checks', rateLimits.paymentChecks(), async (req, res) => {
    const body = parse(paymentBody, req.body);
    res.status(201).json(toReport(await payments.check(uidOf(req), body)));
  });

  // ── Reports ──
  r.get('/reports', async (req, res) => {
    const { limit } = parse(z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }), req.query);
    res.json(await reports.list(uidOf(req), limit));
  });
  r.get('/reports/:id', async (req, res) => {
    const { id } = parse(idParam, req.params);
    res.json(await reports.get(uidOf(req), id));
  });
  r.delete('/reports/:id', async (req, res) => {
    const { id } = parse(idParam, req.params);
    await reports.delete(uidOf(req), id);
    deps.audit.record({ action: 'report.deleted', uid: uidOf(req) });
    res.status(204).end();
  });

  // ── Alerts ──
  r.get('/alerts', async (req, res) => {
    const { unreviewed } = parse(z.object({ unreviewed: z.enum(['true', 'false']).optional() }), req.query);
    res.json(await alerts.list(uidOf(req), unreviewed === 'true'));
  });
  r.post('/alerts/:id/review', async (req, res) => {
    const { id } = parse(idParam, req.params);
    res.json(await alerts.markReviewed(uidOf(req), id));
  });

  // ── Settings, privacy & devices ──
  r.get('/settings', async (req, res) => {
    res.json(await settings.get(uidOf(req)));
  });
  r.put('/settings', async (req, res) => {
    const body = parse(
      z.object({
        pushNotifications: z.boolean().optional(),
        showDomainInNotifications: z.boolean().optional(),
        reportRetentionDays: z.number().int().optional(),
      }).strict(),
      req.body,
    );
    res.json(await settings.update(uidOf(req), body));
  });
  r.get('/privacy', (_req, res) => {
    res.json(settings.privacyStatement());
  });
  r.post('/devices', async (req, res) => {
    const body = parse(z.object({ token: z.string().min(10).max(4096), platform: z.enum(['ios', 'android']) }), req.body);
    const uid = uidOf(req);
    const id = sha256(`${uid}:${body.token}`).slice(0, 40);
    await store.devices.put({ id, uid, token: body.token, platform: body.platform, createdAt: clock.now().toISOString() });
    res.status(204).end();
  });
  r.delete('/devices', async (req, res) => {
    const { token } = parse(z.object({ token: z.string().min(10).max(4096) }), req.body);
    const uid = uidOf(req);
    await store.devices.delete(sha256(`${uid}:${token}`).slice(0, 40));
    res.status(204).end();
  });

  // ── Sandbox ──
  r.post('/sandbox/sessions', rateLimits.sandbox(), async (req, res) => {
    const body = parse(urlBody.extend({ acknowledgeRisk: z.boolean().optional() }), req.body);
    res.status(201).json(await sandbox.create(uidOf(req), body));
  });
  r.get('/sandbox/sessions/:id', async (req, res) => {
    const { id } = parse(idParam, req.params);
    res.json(await sandbox.get(uidOf(req), id));
  });
  r.delete('/sandbox/sessions/:id', async (req, res) => {
    const { id } = parse(idParam, req.params);
    res.json(await sandbox.close(uidOf(req), id));
  });

  return r;
}
