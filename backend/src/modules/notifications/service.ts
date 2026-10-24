import { SEVERITY_RANK, type Alert, type Finding } from '@authentik/shared';
import type { Logger } from 'pino';
import type { Store } from '../../storage/types.js';
import type { AlertDoc, ReportDoc } from '../../storage/models.js';
import { notFound } from '../../lib/errors.js';
import { newId, type Clock } from '../../lib/ids.js';
import type { SettingsService } from '../settings/service.js';
import type { AuditLog } from '../../security/audit/index.js';

/**
 * Alert policy: alerts are for meaningful security events, not every warning.
 * A report raises at most one alert, and the same event on the same domain
 * is not re-alerted within the dedupe window.
 */
const ALERT_CODES = new Set([
  'reputation_match',
  'credential_harvest',
  'lookalike_domain',
  'brand_in_subdomain',
  'redirect_to_blocked_destination',
  'blocked_destination',
  'isolation_failure',
  'payment_recipient_mismatch',
  'payment_amount_mismatch',
  'unrecognised_payment_redirect',
]);
const DEDUPE_WINDOW_MS = 24 * 60 * 60_000;

export function alertCandidate(report: Pick<ReportDoc, 'verdict' | 'assessment'>): Finding | null {
  const eligible = report.assessment.findings.filter(
    (f) =>
      (f.kind === 'confirmed_threat' && SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high) ||
      (ALERT_CODES.has(f.code) && SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high),
  );
  if (eligible.length) return eligible[0]!; // findings are pre-sorted by the risk engine
  if (report.verdict === 'high_risk') {
    return report.assessment.findings.find((f) => f.kind === 'suspicious_indicator' || f.kind === 'confirmed_threat') ?? null;
  }
  return null;
}

export interface PushSender {
  send(tokens: string[], message: { title: string; body: string; alertId: string }): Promise<{ invalidTokens: string[] }>;
}

export class AlertService {
  constructor(
    private readonly store: Store,
    private readonly settings: SettingsService,
    private readonly push: PushSender | null,
    private readonly audit: AuditLog,
    private readonly log: Logger,
    private readonly clock: Clock,
  ) {}

  /** Evaluates a saved report against the alert policy. Never throws: alerting must not fail a scan. */
  async evaluate(report: ReportDoc): Promise<Alert | null> {
    try {
      const f = alertCandidate(report);
      if (!f) return null;
      const domain = report.target.registrableDomain ?? report.target.hostname;
      const dedupeKey = `${f.code}:${domain}`;
      const now = this.clock.now();
      const recent = await this.store.alerts.listByUser(report.uid, { where: { field: 'dedupeKey', equals: dedupeKey }, limit: 5 });
      if (recent.some((a) => now.getTime() - new Date(a.createdAt).getTime() < DEDUPE_WINDOW_MS)) return null;

      const alert: AlertDoc = {
        id: newId(),
        uid: report.uid,
        reportId: report.id,
        code: f.code,
        title: f.title,
        summary: report.headline,
        hostname: report.target.hostname,
        severity: f.severity,
        createdAt: now.toISOString(),
        reviewedAt: null,
        dedupeKey,
        // Alerts live exactly as long as the report they came from.
        expiresAt: report.expiresAt,
      };
      await this.store.alerts.put(alert);
      this.audit.record({ action: 'alert.created', uid: report.uid, hostname: report.target.hostname, outcome: f.code });
      await this.notify(alert);
      return strip(alert);
    } catch (err) {
      this.log.warn({ err }, 'alert evaluation failed');
      return null;
    }
  }

  private async notify(alert: AlertDoc) {
    if (!this.push) return;
    const settings = await this.settings.get(alert.uid);
    if (!settings.pushNotifications) return;
    const devices = await this.store.devices.listByUser(alert.uid, { limit: 10 });
    if (!devices.length) return;
    // Lock-screen safe: no URL, no amounts, and the domain only if the user opted in.
    const body =
      settings.showDomainInNotifications && alert.hostname
        ? `Authentik flagged a potential threat on ${alert.hostname}. Open the app to review.`
        : 'Authentik flagged a potential threat. Open the app to review.';
    const { invalidTokens } = await this.push.send(
      devices.map((d) => d.token),
      { title: 'Security alert', body, alertId: alert.id },
    );
    await Promise.all(devices.filter((d) => invalidTokens.includes(d.token)).map((d) => this.store.devices.delete(d.id)));
  }

  async list(uid: string, unreviewedOnly = false): Promise<Alert[]> {
    const docs = await this.store.alerts.listByUser(uid, {
      limit: 100,
      where: unreviewedOnly ? { field: 'reviewedAt', equals: null } : undefined,
    });
    return docs.map(strip);
  }

  async markReviewed(uid: string, id: string): Promise<Alert> {
    const doc = await this.store.alerts.get(id);
    if (!doc || doc.uid !== uid) throw notFound('Alert not found.');
    const reviewedAt = doc.reviewedAt ?? this.clock.now().toISOString();
    await this.store.alerts.update(id, { reviewedAt });
    return strip({ ...doc, reviewedAt });
  }
}

function strip(doc: AlertDoc): Alert {
  const { uid: _u, dedupeKey: _d, expiresAt: _e, ...alert } = doc;
  return alert;
}
