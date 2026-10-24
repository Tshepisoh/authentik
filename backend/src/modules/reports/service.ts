import type { Report, ReportSummary } from '@authentik/shared';
import type { Store } from '../../storage/types.js';
import type { ReportDoc } from '../../storage/models.js';
import { notFound } from '../../lib/errors.js';
import { addDays, newId, type Clock } from '../../lib/ids.js';
import type { SettingsService } from '../settings/service.js';

export type NewReport = Omit<Report, 'id' | 'createdAt' | 'expiresAt' | 'verdict' | 'completeness' | 'headline'>;

export class ReportService {
  constructor(
    private readonly store: Store,
    private readonly settings: SettingsService,
    private readonly clock: Clock,
  ) {}

  async create(uid: string, input: NewReport): Promise<ReportDoc> {
    const now = this.clock.now();
    const { reportRetentionDays } = await this.settings.get(uid);
    const doc: ReportDoc = {
      ...input,
      id: newId(),
      uid,
      verdict: input.assessment.verdict,
      completeness: input.assessment.completeness,
      headline: input.assessment.headline,
      createdAt: now.toISOString(),
      expiresAt: addDays(now, reportRetentionDays).toISOString(),
    };
    await this.store.reports.put(doc);
    return doc;
  }

  async list(uid: string, limit = 50): Promise<ReportSummary[]> {
    const docs = await this.store.reports.listByUser(uid, { limit });
    return docs.map(toSummary);
  }

  /** Throws 404 for both missing and not-owned reports. */
  async get(uid: string, id: string): Promise<Report> {
    const doc = await this.store.reports.get(id);
    if (!doc || doc.uid !== uid) throw notFound('Report not found.');
    return toReport(doc);
  }

  /** Removes the report and alerts raised from it — matching what the privacy statement promises. */
  async delete(uid: string, id: string): Promise<void> {
    const doc = await this.store.reports.get(id);
    if (!doc || doc.uid !== uid) throw notFound('Report not found.');
    const alerts = await this.store.alerts.listByUser(uid, { where: { field: 'reportId', equals: id }, limit: 100 });
    await Promise.all(alerts.map((a) => this.store.alerts.delete(a.id)));
    await this.store.reports.delete(id);
  }
}

export function toSummary(doc: Report): ReportSummary {
  const { id, type, target, verdict, completeness, headline, createdAt } = doc;
  return { id, type, target, verdict, completeness, headline, createdAt };
}

/** Strips storage-only fields before a report leaves the API. */
export function toReport(doc: ReportDoc | Report): Report {
  const { uid: _uid, ...rest } = doc as ReportDoc;
  return rest;
}
