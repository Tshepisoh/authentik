import type { PrivacyStatement, UserSettings } from '@authentik/shared';
import type { Config } from '../../config.js';
import type { Store } from '../../storage/types.js';
import { badRequest } from '../../lib/errors.js';
import type { Clock } from '../../lib/ids.js';

export class SettingsService {
  constructor(
    private readonly store: Store,
    private readonly config: Config,
    private readonly clock: Clock,
  ) {}

  defaults(): UserSettings {
    return {
      pushNotifications: false,
      showDomainInNotifications: false,
      reportRetentionDays: this.config.REPORT_RETENTION_DAYS_DEFAULT,
    };
  }

  async get(uid: string): Promise<UserSettings> {
    const doc = await this.store.settings.get(uid);
    if (!doc) return this.defaults();
    const { pushNotifications, showDomainInNotifications, reportRetentionDays } = doc;
    return { pushNotifications, showDomainInNotifications, reportRetentionDays };
  }

  async update(uid: string, patch: Partial<UserSettings>): Promise<UserSettings> {
    const { REPORT_RETENTION_DAYS_MIN: min, REPORT_RETENTION_DAYS_MAX: max } = this.config;
    if (patch.reportRetentionDays !== undefined && (patch.reportRetentionDays < min || patch.reportRetentionDays > max)) {
      throw badRequest('invalid_retention', `Report retention must be between ${min} and ${max} days.`);
    }
    const next = { ...(await this.get(uid)), ...patch };
    const now = this.clock.now().toISOString();
    const existing = await this.store.settings.get(uid);
    await this.store.settings.put({ id: uid, uid, createdAt: existing?.createdAt ?? now, updatedAt: now, ...next });
    return next;
  }

  /** Describes what the backend actually does. Keep in sync with docs/data-retention.md. */
  privacyStatement(): PrivacyStatement {
    const c = this.config;
    return {
      reportRetentionDays: { default: c.REPORT_RETENTION_DAYS_DEFAULT, min: c.REPORT_RETENTION_DAYS_MIN, max: c.REPORT_RETENTION_DAYS_MAX },
      collected: [
        'Your email address and sign-in identifier (managed by Firebase Authentication).',
        'Scan, payment-check and Sandbox reports: the checked domain, a redacted address (query values and token-like path parts removed), findings and verdict.',
        'Alerts raised from those reports, and whether you reviewed them.',
        'Your settings, and a push-notification token for each device if you enable notifications.',
        'Security audit logs containing a pseudonymous ID, action, domain and outcome.',
        'On Android, when you check a notification’s links online: the app that posted it, the hostnames of its links and the codes of the warnings your phone raised. Not the notification text, and nothing is saved.',
      ],
      notCollected: [
        'Passwords (Firebase handles sign-in; Authentik never sees your password).',
        'Banking credentials, card numbers or payment authorisations.',
        'Full URLs with query strings, page content or screenshots from scans.',
        'Anything you type or view inside the Sandbox — the remote browser and its data are destroyed when the session ends.',
        'Your contacts, location or browsing history outside Authentik.',
        'The text of your notifications. Notification checks run on your phone.',
        'The websites you visit. Android web protection checks site names on your phone and keeps only the ones it blocked or warned about, on the phone.',
      ],
      deletion: {
        reportDeletion: 'Deleting a report removes the report and any alerts raised from it. It does not remove security audit log entries.',
        accountDeletion:
          'Deleting your account permanently removes your profile, settings, devices, reports, alerts and Sandbox session records, ends any active Sandbox session, and deletes your sign-in account.',
        auditLogs:
          'Security audit logs use a pseudonymous ID that cannot be read back to your account, and are kept for up to 90 days for abuse prevention and incident response.',
      },
    };
  }
}
