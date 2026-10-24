import type { BrandEntry, ThreatListUpdate } from '@authentik/shared';
import type { Config } from '../../config.js';
import { sha256, type Clock } from '../../lib/ids.js';
import type { EntityRegistry } from '../merchant-verification/registry.js';
import type { ThreatListSource } from '../reputation/index.js';

interface Snapshot {
  version: string;
  generatedAt: string;
  domains: Map<string, string>;
  brands: BrandEntry[];
}

/**
 * The list phones use for offline checks: known-bad domains from the local
 * blocklist and threat feeds, plus the brands to watch for impersonation.
 * It holds no user data. Recent snapshots are kept so a phone that is one or
 * two versions behind gets a delta instead of the whole list.
 */
export class ThreatListService {
  private snapshots: Snapshot[] = [];
  private builtAt = 0;

  constructor(
    private readonly deps: { sources: ThreatListSource[]; registry: EntityRegistry; config: Config; clock: Clock },
    private readonly opts: { keepSnapshots?: number; rebuildAfterMs?: number } = {},
  ) {}

  update(since?: string): ThreatListUpdate {
    const cur = this.current();
    const base = {
      version: cur.version,
      generatedAt: cur.generatedAt,
      brands: cur.brands,
      maxAgeSeconds: this.deps.config.THREAT_LIST_MAX_AGE_SECONDS,
    };
    if (since === cur.version) return { ...base, full: false, added: [], removed: [] };

    const old = since ? this.snapshots.find((s) => s.version === since) : undefined;
    if (!old) {
      return { ...base, full: true, added: [...cur.domains].map(([domain, threatType]) => ({ domain, threatType })), removed: [] };
    }
    const added = [...cur.domains]
      .filter(([d, t]) => old.domains.get(d) !== t)
      .map(([domain, threatType]) => ({ domain, threatType }));
    const removed = [...old.domains.keys()].filter((d) => !cur.domains.has(d));
    return { ...base, full: false, added, removed };
  }

  private current(): Snapshot {
    const now = this.deps.clock.now().getTime();
    const latest = this.snapshots.at(-1);
    if (latest && now - this.builtAt < (this.opts.rebuildAfterMs ?? 60_000)) return latest;
    this.builtAt = now;

    const domains = new Map<string, string>();
    // Earlier sources win: the curated blocklist outranks bulk feeds.
    for (const source of this.deps.sources) {
      for (const e of source.entries()) if (!domains.has(e.domain)) domains.set(e.domain, e.threatType);
    }
    const sorted = new Map([...domains].sort(([a], [b]) => (a < b ? -1 : 1)).slice(0, this.deps.config.THREAT_LIST_MAX_ENTRIES));
    const brands = this.brands();
    const version = sha256(JSON.stringify([[...sorted], brands])).slice(0, 16);
    if (latest?.version === version) return latest;

    const snap: Snapshot = { version, generatedAt: new Date(now).toISOString(), domains: sorted, brands };
    this.snapshots = [...this.snapshots, snap].slice(-(this.opts.keepSnapshots ?? 5));
    return snap;
  }

  private brands(): BrandEntry[] {
    const includeDemo = this.deps.config.NODE_ENV !== 'production';
    return this.deps.registry.entities
      .filter((e) => includeDemo || !e.demo)
      .map((e) => ({
        name: e.name,
        isBank: e.kind === 'bank',
        domains: e.domains,
        brandTokens: e.brandTokens,
        mentions: [...new Set([e.name.toLowerCase(), ...(e.aliases ?? [])])],
      }));
  }
}
