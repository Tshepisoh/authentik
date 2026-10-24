import type { CheckRun, Finding } from '@authentik/shared';
import { finding } from '../risk-engine/engine.js';
import type { SafeFetcher } from '../../security/ssrf-protection/index.js';
import type { Clock } from '../../lib/ids.js';
import { TtlCache } from '../../lib/ttl-cache.js';

export interface RegistrationLookup {
  lookup(domain: string): Promise<{ check: CheckRun; findings: Finding[] }>;
}

/**
 * Domain age via RDAP (the structured successor to WHOIS). rdap.org
 * redirects to the authoritative registry; fetched through the SafeFetcher
 * so a hostile RDAP redirect can't be used to reach internal addresses.
 *
 * A young domain is *not* evidence of fraud on its own — it is reported as a
 * signal, and a missing answer is reported as unknown, never as "old".
 */
export class RdapRegistrationLookup implements RegistrationLookup {
  constructor(
    private readonly fetcher: SafeFetcher,
    private readonly baseUrl: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async lookup(domain: string) {
    const check = (status: CheckRun['status'], detail?: string): CheckRun => ({
      check: 'domain_registration', status, critical: false, detail,
    });

    const res = await this.fetcher.fetch(new URL(encodeURIComponent(domain), this.baseUrl), {
      timeoutMs: 5000,
      maxBytes: 200_000,
      maxRedirects: 3,
      accept: 'application/rdap+json, application/json',
    });
    if (res.status === 404) return { check: check('unavailable', 'the registry has no record for this domain'), findings: [] };
    if (!res.body || res.status !== 200) {
      return { check: check('unavailable', 'registration data is not published for this domain'), findings: [] };
    }

    let registered: Date | null = null;
    try {
      const data = JSON.parse(res.body) as { events?: { eventAction?: string; eventDate?: string }[] };
      const ev = data.events?.find((e) => e.eventAction === 'registration');
      if (ev?.eventDate) registered = new Date(ev.eventDate);
    } catch {
      return { check: check('failed', 'registration data could not be read'), findings: [] };
    }
    if (!registered || Number.isNaN(registered.getTime())) {
      return { check: check('unavailable', 'no registration date was published'), findings: [] };
    }

    const ageDays = Math.floor((this.now().getTime() - registered.getTime()) / 86_400_000);
    const data = { ageDays, registeredOn: registered.toISOString().slice(0, 10) };
    const findings: Finding[] = [];
    if (ageDays < 30) {
      findings.push(finding({
        code: 'recently_registered', source: 'domain_registration', kind: 'suspicious_indicator', severity: 'medium', quality: 'high',
        title: 'Very new domain', data,
        reason: `${domain} was registered ${ageDays} day(s) ago. Many scam shops are set up and abandoned within weeks.`,
      }));
    } else if (ageDays < 180) {
      findings.push(finding({
        code: 'young_domain', source: 'domain_registration', kind: 'suspicious_indicator', severity: 'low', quality: 'high',
        title: 'Recently registered domain', data,
        reason: `${domain} was registered about ${Math.round(ageDays / 30)} month(s) ago.`,
      }));
    } else {
      findings.push(finding({
        code: 'established_domain', source: 'domain_registration', kind: 'reassurance', severity: 'info', quality: 'high',
        title: 'Established domain', data,
        reason: `${domain} has been registered since ${data.registeredOn}. Age alone does not make a site trustworthy.`,
      }));
    }
    return { check: check('completed'), findings };
  }
}

/**
 * Registration dates rarely change, and domain checks from phones repeat the
 * same domains, so answers are reused: a day for a completed lookup, an hour
 * for "not published". Failures are retried next time.
 */
export class CachedRegistrationLookup implements RegistrationLookup {
  private readonly cache: TtlCache<{ check: CheckRun; findings: Finding[] }>;

  constructor(
    private readonly inner: RegistrationLookup,
    clock: Clock,
  ) {
    this.cache = new TtlCache(clock, 5000);
  }

  async lookup(domain: string) {
    const hit = this.cache.get(domain);
    if (hit) return hit;
    const result = await this.inner.lookup(domain);
    const ttl = result.check.status === 'completed' ? 86_400 : result.check.status === 'unavailable' ? 3600 : 0;
    this.cache.set(domain, result, ttl);
    return result;
  }
}
