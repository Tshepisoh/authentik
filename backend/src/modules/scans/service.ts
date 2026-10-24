import {
  publicSuffix,
  redactUrl,
  registrableDomain,
  type CheckRun,
  type DomainAnalysis,
  type DomainCheckDepth,
  type DomainCheckSource,
  type Finding,
  type RedirectHop,
} from '@authentik/shared';
import type { Config } from '../../config.js';
import type { ReportDoc } from '../../storage/models.js';
import type { AuditLog } from '../../security/audit/index.js';
import { validateTargetUrl } from '../../security/url-validation/index.js';
import type { SafeFetchResult, SafeFetchOptions } from '../../security/ssrf-protection/index.js';
import { assess, finding } from '../risk-engine/engine.js';
import type { ReputationService } from '../reputation/index.js';
import type { EntityRegistry } from '../merchant-verification/registry.js';
import type { ReportService } from '../reports/service.js';
import type { AlertService } from '../notifications/service.js';
import { analyzeImpersonation } from './lookalike.js';
import { domainSignals, RESERVED_TLDS } from './domain-signals.js';
import { analyzePage } from './page-evidence.js';
import type { RegistrationLookup } from './registration.js';

export interface PageFetcher {
  fetch(url: URL, options: SafeFetchOptions): Promise<SafeFetchResult>;
}

export interface WebsiteEvidence {
  findings: Finding[];
  checks: CheckRun[];
  redirects: RedirectHop[];
  finalHostname: string;
}

export class ScanService {
  constructor(
    private readonly deps: {
      config: Config;
      registry: EntityRegistry;
      reputation: ReputationService;
      registration: RegistrationLookup | null;
      fetcher: PageFetcher;
      reports: ReportService;
      alerts: AlertService;
      audit: AuditLog;
    },
  ) {}

  /** Full website scan: validate → gather evidence → assess → save → alert. */
  async scan(uid: string, input: string): Promise<ReportDoc> {
    const target = validateTargetUrl(input);

    if (!target.allowed) {
      this.deps.audit.violation({ action: 'scan.blocked', uid, hostname: target.url.hostname, outcome: target.blockCode });
      const assessment = blockedAssessment(target.blockCode, target.blockMessage);
      return this.deps.reports.create(uid, { type: 'website_scan', target: target.summary, assessment, redirects: [] });
    }

    const evidence = await this.gatherWebsiteEvidence(target.url, target.hadCredentials);
    const assessment = assess({ subject: 'website', findings: evidence.findings, checks: evidence.checks });
    const report = await this.deps.reports.create(uid, {
      type: 'website_scan',
      target: target.summary,
      assessment,
      redirects: evidence.redirects,
    });
    this.deps.audit.record({ action: 'scan.created', uid, hostname: target.url.hostname, outcome: assessment.verdict });
    await this.deps.alerts.evaluate(report);
    return report;
  }

  /**
   * Domain check for phones: a hostname from a notification link, the share
   * sheet or (later) a DNS lookup. Nothing is stored. `quick` skips the page
   * fetch, so checking a domain doesn't visit it.
   */
  async analyzeDomain(
    uid: string,
    input: string,
    { depth = 'quick', source = 'manual' }: { depth?: DomainCheckDepth; source?: DomainCheckSource } = {},
  ): Promise<DomainAnalysis> {
    const target = validateTargetUrl(input);
    if (!target.allowed) {
      this.deps.audit.violation({ action: 'domain.blocked', uid, hostname: target.url.hostname, outcome: target.blockCode, detail: source });
      return { target: target.summary, depth, assessment: blockedAssessment(target.blockCode, target.blockMessage) };
    }
    const evidence = await this.gatherWebsiteEvidence(target.url, target.hadCredentials, { fetchPage: depth === 'full' });
    const assessment = assess({ subject: 'website', findings: evidence.findings, checks: evidence.checks });
    this.deps.audit.record({ action: 'domain.analyzed', uid, hostname: target.url.hostname, outcome: assessment.verdict, detail: source });
    return { target: target.summary, depth, assessment };
  }

  /**
   * Evidence about a website, reusable by the Sandbox and payment checks.
   * Network checks run in parallel; each records its own status so a failure
   * shows up as "partial" rather than silently disappearing.
   */
  async gatherWebsiteEvidence(url: URL, hadCredentials = false, { fetchPage = true } = {}): Promise<WebsiteEvidence> {
    const { config, registry, reputation, registration, fetcher } = this.deps;
    const findings: Finding[] = [...domainSignals({ url, hadCredentials })];
    const checks: CheckRun[] = [];

    findings.push(...analyzeImpersonation(url.hostname, registry));
    checks.push({ check: 'lookalike', status: 'completed', critical: false });

    const tld = (publicSuffix(url.hostname) ?? '').split('.').pop() ?? '';
    const simulated = RESERVED_TLDS.has(tld);
    const domain = registrableDomain(url.hostname);

    const [rep, reg, page] = await Promise.all([
      reputation.check(url),
      simulated || !registration || !domain
        ? Promise.resolve(null)
        : registration.lookup(domain),
      simulated || !fetchPage
        ? Promise.resolve(null)
        : fetcher.fetch(url, {
            timeoutMs: config.SCAN_FETCH_TIMEOUT_MS,
            maxBytes: config.SCAN_MAX_BODY_BYTES,
            maxRedirects: config.SCAN_MAX_REDIRECTS,
          }),
    ]);

    findings.push(...rep.findings);
    checks.push(...rep.checks);

    if (reg) {
      findings.push(...reg.findings);
      checks.push(reg.check);
    } else {
      checks.push({
        check: 'domain_registration',
        status: 'skipped',
        critical: false,
        detail: simulated ? 'simulated domain' : registration ? 'no registrable domain' : 'disabled',
      });
    }

    let redirects: RedirectHop[] = [];
    let finalHostname = url.hostname;
    if (page) {
      const pageEvidence = analyzePage(url, page, registry);
      findings.push(...pageEvidence.findings);
      checks.push(pageEvidence.check);
      // Fetchers already redact; re-redact so no fetcher implementation can leak query values into storage.
      redirects = page.hops.map((h) => ({ ...h, url: redactUrl(h.url) }));
      finalHostname = page.finalUrl.hostname;

      // If we were forwarded elsewhere, the destination is what the user will actually see.
      if (registrableDomain(page.finalUrl.hostname) !== domain && !page.blocked && !page.error) {
        findings.push(...analyzeImpersonation(page.finalUrl.hostname, registry).filter((f) => f.kind !== 'reassurance'));
        const finalRep = await reputation.check(page.finalUrl);
        findings.push(...finalRep.findings);
        checks.push(...finalRep.checks.map((c) => ({ ...c, check: `${c.check}.destination` })));
      }
    } else {
      checks.push({ check: 'page_evidence', status: 'skipped', critical: false, detail: simulated ? 'simulated domain' : 'quick check' });
    }

    return { findings, checks, redirects, finalHostname };
  }
}

function blockedAssessment(blockCode: string, blockMessage: string) {
  return assess({
    subject: 'website',
    findings: [finding({
      code: 'scan_blocked', source: 'url_policy', kind: 'unknown', severity: 'info', quality: 'high', hardBlock: true,
      title: 'Address not permitted', reason: blockMessage, data: { policy: blockCode },
    })],
    checks: [{ check: 'url_policy', status: 'completed', critical: true, detail: blockCode }],
  });
}
