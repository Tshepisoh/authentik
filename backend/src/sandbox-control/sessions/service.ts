import type WebSocket from 'ws';
import type { Logger } from 'pino';
import {
  redactUrl,
  type CreateSandboxSessionRequest,
  type Report,
  type SandboxEvent,
  type SandboxSessionResponse,
} from '@authentik/shared';
import type { Config } from '../../config.js';
import type { Store } from '../../storage/types.js';
import type { SandboxSessionDoc } from '../../storage/models.js';
import { HttpError, conflict, notFound, unavailable } from '../../lib/errors.js';
import { addDays, addSeconds, newId, safeEqual, sha256, type Clock } from '../../lib/ids.js';
import type { AuditLog } from '../../security/audit/index.js';
import { summarizeTarget, validateTargetUrl } from '../../security/url-validation/index.js';
import { assess, finding } from '../../modules/risk-engine/engine.js';
import type { ScanService } from '../../modules/scans/service.js';
import type { ReportService } from '../../modules/reports/service.js';
import { toReport, toSummary } from '../../modules/reports/service.js';
import type { AlertService } from '../../modules/notifications/service.js';
import type { SandboxWorker, WorkerExtraction } from '../workers/client.js';
import { clientMessageSchema, findingsFromEvents, preflight, workerMessageSchema } from '../policies/index.js';

interface ActiveSession {
  id: string;
  uid: string;
  upstream: WebSocket;
  viewer: WebSocket | null;
  events: SandboxEvent[];
  visitedHosts: Set<string>;
  startedAt: Date;
  expiresAt: number;
  lastActivity: number;
  invalidUpstream: number;
  /** Token bucket for viewer input. */
  bucket: { tokens: number; at: number };
  closing: Promise<Report> | null;
}

const MAX_EVENTS = 500;
const FAILURE_REASONS = new Set(['isolation_failure', 'browser_crashed', 'worker_disconnected', 'worker_protocol_error']);

/**
 * Lifecycle manager for Sandbox sessions. One record per session in the
 * store; live state (sockets, timers) in memory on the instance that owns the
 * session. With more than one API instance, route a session's traffic to its
 * owner (sticky sessions keyed on the session id).
 */
export class SandboxService {
  private readonly active = new Map<string, ActiveSession>();
  private reaper: NodeJS.Timeout | null = null;

  constructor(
    private readonly deps: {
      config: Config;
      store: Store;
      worker: SandboxWorker;
      scans: ScanService;
      reports: ReportService;
      alerts: AlertService;
      audit: AuditLog;
      log: Logger;
      clock: Clock;
    },
  ) {}

  start() {
    this.reaper ??= setInterval(() => void this.reap(), 5000);
    this.reaper.unref();
  }

  async stop() {
    if (this.reaper) clearInterval(this.reaper);
    this.reaper = null;
    await Promise.all([...this.active.values()].map((a) => this.finish(a, 'server_shutdown')));
  }

  get activeCount() {
    return this.active.size;
  }

  async create(uid: string, req: CreateSandboxSessionRequest): Promise<SandboxSessionResponse> {
    const { config, worker, store, audit, clock } = this.deps;
    // Fail closed: no worker means no Sandbox, never a direct fallback.
    if (!worker.configured) {
      throw unavailable('sandbox_unavailable', 'The Sandbox is not available right now. The site was not opened.');
    }

    const target = validateTargetUrl(req.url);
    const scan = await this.deps.scans.scan(uid, req.url);
    preflight(scan.verdict, req.acknowledgeRisk);

    const mine = [...this.active.values()].filter((a) => a.uid === uid).length;
    if (mine >= config.SANDBOX_MAX_SESSIONS_PER_USER) {
      throw conflict('sandbox_session_limit', 'You already have a Sandbox session open. Close it to start another.');
    }

    const id = newId();
    const viewToken = newId(32);
    const now = clock.now();
    const sessionExpiresAt = addSeconds(now, config.SANDBOX_SESSION_TTL_SECONDS);
    const viewport = { width: config.SANDBOX_VIEWPORT_WIDTH, height: config.SANDBOX_VIEWPORT_HEIGHT };
    const doc: SandboxSessionDoc = {
      id, uid,
      state: 'starting',
      displayUrl: target.summary.displayUrl,
      hostname: target.url.hostname,
      scanReportId: scan.id,
      viewTokenHash: sha256(viewToken),
      sessionExpiresAt: sessionExpiresAt.toISOString(),
      createdAt: now.toISOString(),
      expiresAt: addDays(now, config.REPORT_RETENTION_DAYS_MAX).toISOString(),
      lastActivityAt: now.toISOString(),
      endedAt: null, endReason: null, events: [], visitedHosts: [target.url.hostname], reportId: null,
    };
    await store.sandboxSessions.put(doc);

    let upstream: WebSocket;
    try {
      await worker.createSession({ sessionId: id, url: target.url.href, viewport, ttlSeconds: config.SANDBOX_SESSION_TTL_SECONDS });
      upstream = await openSocket(worker.openStream(id), 10_000);
    } catch (err) {
      await worker.closeSession(id);
      await store.sandboxSessions.update(id, { state: 'failed', endReason: 'isolation_unavailable', endedAt: clock.now().toISOString(), viewTokenHash: '' });
      audit.record({ action: 'sandbox.refused', uid, hostname: target.url.hostname, outcome: 'isolation_unavailable', detail: (err as Error).message });
      throw unavailable(
        'isolation_unavailable',
        'The Sandbox could not set up an isolated browser, so the site was not opened. Please try again shortly.',
      );
    }

    const session: ActiveSession = {
      id, uid, upstream, viewer: null, events: [], visitedHosts: new Set([target.url.hostname]),
      startedAt: now, expiresAt: sessionExpiresAt.getTime(), lastActivity: Date.now(), invalidUpstream: 0,
      bucket: { tokens: 40, at: Date.now() }, closing: null,
    };
    this.active.set(id, session);
    this.wireUpstream(session);
    await store.sandboxSessions.update(id, { state: 'active' });
    audit.record({ action: 'sandbox.created', uid, hostname: target.url.hostname });

    return {
      sessionId: id,
      state: 'active',
      viewToken,
      streamPath: `/v1/sandbox/sessions/${id}/stream`,
      expiresAt: doc.sessionExpiresAt,
      viewport,
      scan: toSummary(scan),
    };
  }

  async get(uid: string, id: string) {
    const doc = await this.deps.store.sandboxSessions.get(id);
    if (!doc || doc.uid !== uid) throw notFound('Session not found.');
    const { viewTokenHash: _h, uid: _u, ...rest } = doc;
    return rest;
  }

  /** Ends a session the user owns and returns its report. Idempotent. */
  async close(uid: string, id: string, reason = 'user_closed'): Promise<Report> {
    const doc = await this.deps.store.sandboxSessions.get(id);
    if (!doc || doc.uid !== uid) throw notFound('Session not found.');
    const active = this.active.get(id);
    if (active) return this.finish(active, reason);
    if (doc.reportId) return this.deps.reports.get(uid, doc.reportId);
    throw conflict('sandbox_session_ended', 'This session has already ended.');
  }

  /** Reads payment details from the page the user's live session is showing. Owner only. */
  async readPayment(uid: string, id: string): Promise<WorkerExtraction> {
    const session = this.active.get(id);
    if (!session || session.uid !== uid) throw notFound('Session not found or already ended.');
    if (!this.deps.worker.extractFromSession) throw unavailable('extraction_unavailable', 'Reading the page is not available right now.');
    session.lastActivity = Date.now();
    const result = await this.deps.worker.extractFromSession(id).catch(() => {
      throw unavailable('page_unreadable', 'The page could not be read. Enter the details yourself instead.');
    });
    if (!result) throw notFound('Session not found or already ended.');
    return result;
  }

  async closeAllForUser(uid: string) {
    await Promise.all([...this.active.values()].filter((a) => a.uid === uid).map((a) => this.finish(a, 'account_deleted')));
  }

  /** Connects a viewer socket. The view token is single-session, short-lived and revoked on close. */
  async attachViewer(id: string, token: string, ws: WebSocket): Promise<void> {
    const session = this.active.get(id);
    const doc = session ? await this.deps.store.sandboxSessions.get(id) : null;
    if (!session || !doc || !doc.viewTokenHash || !safeEqual(sha256(token), doc.viewTokenHash)) {
      ws.close(4401, 'unauthorized');
      return;
    }
    if (session.viewer && session.viewer !== ws) session.viewer.close(4409, 'replaced by a newer viewer');
    session.viewer = ws;
    session.lastActivity = Date.now();

    ws.on('message', (raw) => void this.onViewerMessage(session, raw.toString()));
    ws.on('close', () => {
      if (session.viewer === ws) session.viewer = null;
    });
  }

  private async onViewerMessage(session: ActiveSession, raw: string) {
    if (!this.take(session)) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }
    const msg = clientMessageSchema.safeParse(parsed);
    if (!msg.success) return;
    session.lastActivity = Date.now();

    if (msg.data.type === 'navigate') {
      let href: string | null = null;
      try {
        const t = validateTargetUrl(msg.data.url);
        if (t.allowed) href = t.url.href;
      } catch (err) {
        if (!(err instanceof HttpError)) throw err;
      }
      if (!href) {
        // The user asked for this, not the site: tell the viewer, audit it, but keep it out of the site's findings.
        this.deps.audit.violation({ action: 'policy.violation', uid: session.uid, outcome: 'sandbox_navigate_blocked' });
        this.sendViewer(session, {
          type: 'event',
          event: { type: 'blocked_destination', at: new Date().toISOString(), severity: 'warning', detail: 'that address is not permitted in the Sandbox' },
        });
        return;
      }
      session.upstream.send(JSON.stringify({ type: 'navigate', url: href }));
      return;
    }
    session.upstream.send(JSON.stringify(msg.data));
  }

  private take(session: ActiveSession): boolean {
    const now = Date.now();
    const b = session.bucket;
    b.tokens = Math.min(40, b.tokens + ((now - b.at) / 1000) * 30);
    b.at = now;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  private wireUpstream(session: ActiveSession) {
    const { upstream } = session;
    upstream.on('message', (raw) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString());
      } catch {
        parsed = null;
      }
      const msg = workerMessageSchema.safeParse(parsed);
      if (!msg.success) {
        // A worker that speaks garbage may be compromised; don't keep relaying it.
        if (++session.invalidUpstream > 20) void this.finish(session, 'worker_protocol_error');
        return;
      }
      const m = msg.data;
      switch (m.type) {
        case 'frame': {
          const v = session.viewer;
          // Drop frames under back-pressure rather than buffering unboundedly.
          if (v && v.readyState === v.OPEN && v.bufferedAmount < 2_000_000) v.send(JSON.stringify(m));
          break;
        }
        case 'navigated': {
          let shown = '[unknown]';
          try {
            const u = new URL(m.url);
            session.visitedHosts.add(u.hostname);
            shown = redactUrl(u);
          } catch {
            /* ignore */
          }
          this.sendViewer(session, { type: 'navigated', url: shown, title: m.title });
          break;
        }
        case 'event':
          this.recordEvent(session, m.event);
          if (m.event.type === 'isolation_failure') {
            this.deps.audit.record({ action: 'sandbox.isolation_failure', uid: session.uid, detail: m.event.detail });
            this.deps.log.error({ sessionId: session.id }, 'sandbox isolation failure');
            void this.finish(session, 'isolation_failure');
          } else if (m.event.type === 'browser_crashed') {
            void this.finish(session, 'browser_crashed');
          }
          break;
        case 'closed':
          void this.finish(session, m.reason);
          break;
      }
    });
    upstream.on('close', () => void this.finish(session, 'worker_disconnected'));
    upstream.on('error', () => void this.finish(session, 'worker_disconnected'));
  }

  private recordEvent(session: ActiveSession, event: SandboxEvent) {
    if (session.events.length < MAX_EVENTS) session.events.push(event);
    if (event.severity !== 'info') {
      this.deps.audit.record({ action: 'sandbox.security_event', uid: session.uid, hostname: event.target, outcome: event.type });
    }
    this.sendViewer(session, { type: 'event', event });
  }

  private sendViewer(session: ActiveSession, msg: unknown) {
    const v = session.viewer;
    if (v && v.readyState === v.OPEN) v.send(JSON.stringify(msg));
  }

  private finish(session: ActiveSession, reason: string): Promise<Report> {
    session.closing ??= this.doFinish(session, reason);
    return session.closing;
  }

  private async doFinish(session: ActiveSession, reason: string): Promise<Report> {
    const { store, worker, reports, alerts, audit, clock } = this.deps;
    this.active.delete(session.id);
    const endedAt = clock.now();

    this.sendViewer(session, { type: 'closed', reason });
    session.viewer?.close(1000, 'session ended');
    session.upstream.removeAllListeners('close');
    session.upstream.close();
    // Always tell the worker to destroy the browser, even if it already reported closing.
    await worker.closeSession(session.id);

    const doc = await store.sandboxSessions.get(session.id);
    const failed = FAILURE_REASONS.has(reason);
    const findings = findingsFromEvents(session.events, doc?.hostname);
    if (failed) {
      findings.push(finding({
        code: reason === 'isolation_failure' ? 'isolation_failure' : 'sandbox_session_failed',
        source: 'sandbox', kind: 'unknown', severity: 'info', quality: 'high',
        title: reason === 'isolation_failure' ? 'Session stopped for safety' : 'Session ended unexpectedly',
        reason: reason === 'isolation_failure'
          ? 'Authentik could not confirm the browser was still isolated, so the session was stopped immediately.'
          : 'The remote browser stopped before the session finished, so observation is incomplete.',
      }));
    }
    const assessment = assess({
      subject: 'sandbox',
      findings,
      checks: [
        { check: 'sandbox_session', status: failed ? 'failed' : 'completed', critical: true, detail: reason.replace(/_/g, ' ') },
      ],
      now: endedAt,
    });

    const target = {
      ...summarizeTarget(new URL(`https://${doc?.hostname ?? 'unknown.invalid'}/`)),
      ...(doc && { displayUrl: doc.displayUrl }),
    };
    const report = await reports.create(session.uid, {
      type: 'sandbox_session',
      target,
      assessment,
      redirects: [],
      relatedReportId: doc?.scanReportId,
      sandbox: {
        sessionId: session.id,
        startedAt: session.startedAt.toISOString(),
        endedAt: endedAt.toISOString(),
        endReason: reason,
        events: session.events,
        visitedHosts: [...session.visitedHosts],
      },
    });
    await alerts.evaluate(report);
    await store.sandboxSessions.update(session.id, {
      state: failed ? 'failed' : 'closed',
      endedAt: endedAt.toISOString(),
      endReason: reason,
      events: session.events,
      visitedHosts: [...session.visitedHosts],
      reportId: report.id,
      viewTokenHash: '', // revoke viewing credentials
    });
    audit.record({ action: 'sandbox.closed', uid: session.uid, hostname: doc?.hostname, outcome: reason });
    return toReport(report);
  }

  private async reap() {
    const now = Date.now();
    const idleMs = this.deps.config.SANDBOX_IDLE_TIMEOUT_SECONDS * 1000;
    for (const s of [...this.active.values()]) {
      if (now >= s.expiresAt) {
        this.recordEvent(s, { type: 'session_expired', at: new Date().toISOString(), severity: 'info', detail: 'time limit reached' });
        await this.finish(s, 'expired').catch((err) => this.deps.log.warn({ err }, 'reap failed'));
      } else if (!s.viewer && now - s.lastActivity > idleMs) {
        await this.finish(s, 'idle_timeout').catch((err) => this.deps.log.warn({ err }, 'reap failed'));
      }
    }
  }
}

function openSocket(ws: WebSocket, timeoutMs: number): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new Error('stream open timeout'));
    }, timeoutMs);
    ws.once('open', () => {
      clearTimeout(timer);
      resolve(ws);
    });
    ws.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}
