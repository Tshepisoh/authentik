import { readFileSync } from 'node:fs';
import type { Logger } from 'pino';
import type { CheckRun, Finding, ThreatEntry } from '@authentik/shared';
import { checkHostname, isSameOrSubdomain } from '@authentik/shared';
import { finding } from '../risk-engine/engine.js';
import { systemClock, type Clock } from '../../lib/ids.js';
import { TtlCache } from '../../lib/ttl-cache.js';

export type ReputationResult =
  | { status: 'completed'; matches: { threatType: string }[] }
  | { status: 'unavailable' | 'failed'; detail: string };

export interface ReputationProvider {
  /** Used as the check name: `reputation.<id>`. */
  id: string;
  label: string;
  /** If this provider can't answer, the scan can't be "no obvious warnings". */
  critical: boolean;
  check(url: URL): Promise<ReputationResult>;
  /** Set on remote providers whose answers can be reused for a while. */
  cacheTtlSeconds?: number;
}

/** A provider that can also hand its known-bad domains to phones (`GET /v1/threats/updates`). */
export interface ThreatListSource {
  readonly id: string;
  entries(): ThreatEntry[];
}

export const isThreatListSource = <T,>(p: T): p is T & ThreatListSource =>
  typeof (p as ThreatListSource).entries === 'function';

/**
 * Google Safe Browsing v4 Lookup API.
 *
 * Free, with no billing account. Google's terms limit it to non-commercial use,
 * which covers the current testing stage. A commercial launch needs a commercial
 * provider (e.g. Google Web Risk, which needs billing), added as another
 * `ReputationProvider`.
 *
 * Privacy: the lookup API sends the URL to Google. We send scheme, host and
 * path only — never the query string or fragment, which is where session
 * tokens and personal identifiers usually live. The Update API (local
 * hash-prefix matching) avoids sending URLs at all and is the planned upgrade.
 */
export class SafeBrowsingProvider implements ReputationProvider {
  readonly id = 'google_safe_browsing';
  readonly label = 'Google Safe Browsing';
  readonly critical = true;
  readonly cacheTtlSeconds = 1800;

  constructor(
    private readonly apiKey: string | undefined,
    private readonly timeoutMs = 4000,
  ) {}

  async check(url: URL): Promise<ReputationResult> {
    if (!this.apiKey) return { status: 'unavailable', detail: 'no threat-reputation provider is configured' };
    const target = `${url.protocol}//${url.host}${url.pathname}`;
    try {
      const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(this.apiKey)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
        body: JSON.stringify({
          client: { clientId: 'authentik', clientVersion: '0.1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: target }],
          },
        }),
      });
      if (!res.ok) return { status: 'failed', detail: `reputation service returned ${res.status}` };
      const body = (await res.json()) as { matches?: { threatType: string }[] };
      return { status: 'completed', matches: (body.matches ?? []).map((m) => ({ threatType: m.threatType })) };
    } catch {
      return { status: 'failed', detail: 'the reputation service did not respond' };
    }
  }
}

/** Curated local list (known-bad domains from incident reports, loaded from BLOCKLIST_PATH). Low coverage, so not critical. */
export class LocalBlocklistProvider implements ReputationProvider, ThreatListSource {
  readonly id = 'local_blocklist';
  readonly label = 'Authentik blocklist';
  readonly critical = false;
  private readonly domains: string[];

  constructor(entries: string[]) {
    this.domains = entries
      .map((l) => l.trim().toLowerCase())
      .filter((l) => l && !l.startsWith('#'))
      .map((l) => l.replace(/^https?:\/\//, '').split('/')[0]!);
  }

  static fromFile(path: string | undefined, builtIn: string[] = []): LocalBlocklistProvider {
    const extra = path ? readFileSync(path, 'utf8').split(/\r?\n/) : [];
    return new LocalBlocklistProvider([...builtIn, ...extra]);
  }

  async check(url: URL): Promise<ReputationResult> {
    const hit = this.domains.some((d) => isSameOrSubdomain(url.hostname, d));
    return { status: 'completed', matches: hit ? [{ threatType: 'KNOWN_FRAUD' }] : [] };
  }

  entries(): ThreatEntry[] {
    return this.domains.map((domain) => ({ domain, threatType: 'KNOWN_FRAUD' }));
  }
}

/**
 * Plain-text domain feeds the operator configures (`THREAT_FEED_URLS`), e.g.
 * URLhaus's hostfile or OpenPhish's community feed. Accepts one domain or URL
 * per line, or hosts-file lines (`0.0.0.0 bad.example`). Refreshed on a timer.
 * These are operator-chosen URLs, not user input, so plain `fetch` is used.
 * Partial coverage, so not critical.
 */
export class ThreatFeedProvider implements ReputationProvider, ThreatListSource {
  readonly id = 'threat_feeds';
  readonly label = 'Threat feeds';
  readonly critical = false;
  private domains = new Set<string>();
  private loaded = false;
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly urls: string[],
    private readonly log: Logger,
    private readonly opts: { maxEntries?: number; maxBytes?: number; timeoutMs?: number; fetchText?: (url: string) => Promise<string> } = {},
  ) {}

  /** Reloads every feed. If all of them fail, the last good set stays in place. */
  async refresh(): Promise<void> {
    const max = this.opts.maxEntries ?? 200_000;
    const next = new Set<string>();
    let anyOk = false;
    for (const url of this.urls) {
      try {
        const text = await (this.opts.fetchText ?? ((u: string) => this.download(u)))(url);
        anyOk = true;
        for (const d of parseFeed(text)) {
          if (next.size >= max) break;
          next.add(d);
        }
      } catch (e) {
        this.log.warn({ feed: new URL(url).host, err: (e as Error).message }, 'threat feed refresh failed');
      }
    }
    if (anyOk) {
      this.domains = next;
      this.loaded = true;
    }
  }

  start(intervalMinutes: number): void {
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), intervalMinutes * 60_000);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async check(url: URL): Promise<ReputationResult> {
    if (!this.loaded) return { status: 'unavailable', detail: 'threat feeds have not loaded yet' };
    // A listed domain covers its subdomains.
    const labels = url.hostname.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      if (this.domains.has(labels.slice(i).join('.'))) return { status: 'completed', matches: [{ threatType: 'FEED_LISTED' }] };
    }
    return { status: 'completed', matches: [] };
  }

  entries(): ThreatEntry[] {
    return [...this.domains].map((domain) => ({ domain, threatType: 'FEED_LISTED' }));
  }

  private async download(url: string): Promise<string> {
    const res = await fetch(url, { signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000) });
    if (!res.ok) throw new Error(`status ${res.status}`);
    const text = await res.text();
    if (text.length > (this.opts.maxBytes ?? 30_000_000)) throw new Error('feed too large');
    return text;
  }
}

/** Hostnames from a feed body. Lines that aren't a public hostname are dropped. */
export function parseFeed(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim().toLowerCase();
    if (!line) continue;
    const parts = line.split(/\s+/);
    // hosts-file format: "0.0.0.0 bad.example"
    let host = parts.length > 1 && /^(0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0]!) ? parts[1]! : parts[0]!;
    host = host.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#:]/)[0]!.replace(/\.$/, '');
    if (!host.includes('.') || /^[\d.]+$/.test(host)) continue;
    if (!checkHostname(host).allowed) continue;
    out.push(host);
  }
  return out;
}


const THREAT_LABELS: Record<string, string> = {
  MALWARE: 'malware',
  SOCIAL_ENGINEERING: 'phishing or deceptive content',
  UNWANTED_SOFTWARE: 'unwanted software',
  POTENTIALLY_HARMFUL_APPLICATION: 'harmful apps',
  KNOWN_FRAUD: 'reported fraud',
  FEED_LISTED: 'reported phishing or malware',
};

export class ReputationService {
  private readonly cache: TtlCache<ReputationResult>;

  constructor(
    readonly providers: ReputationProvider[],
    clock: Clock = systemClock,
  ) {
    this.cache = new TtlCache(clock, 10_000);
  }

  /** Remote answers are cached per provider, host and path. Failures are never cached. */
  private async ask(p: ReputationProvider, url: URL): Promise<ReputationResult> {
    if (!p.cacheTtlSeconds) return p.check(url);
    const key = `${p.id}|${url.protocol}//${url.host}${url.pathname}`;
    const hit = this.cache.get(key);
    if (hit) return hit;
    const r = await p.check(url);
    if (r.status === 'completed') this.cache.set(key, r, p.cacheTtlSeconds);
    return r;
  }

  async check(url: URL): Promise<{ findings: Finding[]; checks: CheckRun[] }> {
    const results = await Promise.all(this.providers.map(async (p) => ({ p, r: await this.ask(p, url) })));
    const findings: Finding[] = [];
    const checks: CheckRun[] = [];
    for (const { p, r } of results) {
      checks.push({
        check: `reputation.${p.id}`,
        status: r.status,
        critical: p.critical,
        detail: r.status === 'completed' ? undefined : r.detail,
      });
      if (r.status !== 'completed') continue;
      for (const m of r.matches) {
        findings.push(
          finding({
            code: 'reputation_match',
            source: 'reputation',
            kind: 'confirmed_threat',
            severity: 'critical',
            quality: 'high',
            title: `Listed as ${THREAT_LABELS[m.threatType] ?? 'malicious'}`,
            reason: `${p.label} lists ${url.hostname} for ${THREAT_LABELS[m.threatType] ?? m.threatType.toLowerCase()}.`,
            data: { provider: p.id, threatType: m.threatType },
          }),
        );
      }
    }
    return { findings, checks };
  }
}
