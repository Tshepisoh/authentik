import type { Logger } from 'pino';
import { createHmac } from 'node:crypto';

export type AuditAction =
  | 'auth.rejected'
  | 'account.deleted'
  | 'account.sessions_revoked'
  | 'scan.created'
  | 'scan.blocked'
  | 'payment_check.created'
  | 'report.deleted'
  | 'sandbox.created'
  | 'sandbox.refused'
  | 'sandbox.closed'
  | 'sandbox.security_event'
  | 'sandbox.isolation_failure'
  | 'policy.violation'
  | 'alert.created'
  | 'domain.analyzed'
  | 'domain.blocked'
  | 'notification.analyzed';

export interface AuditEvent {
  action: AuditAction;
  uid?: string;
  /** Hostname only — never full URLs or query strings. */
  hostname?: string;
  outcome?: string;
  detail?: string;
}

/**
 * Security audit trail. Records *permitted metadata* only: a pseudonymous
 * actor id (HMAC of the uid, so logs survive account deletion without
 * identifying the person), the action, a hostname and an outcome code.
 */
export class AuditLog {
  private readonly violations = new Map<string, { count: number; since: number }>();

  constructor(
    private readonly log: Logger,
    private readonly salt: string,
  ) {}

  actor(uid: string): string {
    return createHmac('sha256', this.salt).update(uid).digest('hex').slice(0, 24);
  }

  record(event: AuditEvent): void {
    const { uid, ...rest } = event;
    this.log.info({ audit: true, actor: uid ? this.actor(uid) : undefined, ...rest }, event.action);
  }

  /**
   * Counts policy violations per actor and escalates to an error-level log
   * (which should page whoever is on call) when one actor keeps hitting them.
   */
  violation(event: AuditEvent & { uid: string }, threshold = 5, windowMs = 10 * 60_000): void {
    this.record({ ...event, action: event.action });
    const key = this.actor(event.uid);
    const now = Date.now();
    const entry = this.violations.get(key);
    const fresh = !entry || now - entry.since > windowMs ? { count: 0, since: now } : entry;
    fresh.count++;
    this.violations.set(key, fresh);
    if (fresh.count === threshold) {
      this.log.error({ audit: true, actor: key, count: fresh.count }, 'repeated policy violations');
    }
  }
}
