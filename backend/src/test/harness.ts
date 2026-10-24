import { pino } from 'pino';
import { testConfig, type Config } from '../config.js';
import { buildDeps, type Overrides } from '../container.js';
import { createApp } from '../app.js';
import type { ReputationProvider, ReputationResult } from '../modules/reputation/index.js';
import type { SafeFetchOptions, SafeFetchResult } from '../security/ssrf-protection/index.js';
import type { PageFetcher } from '../modules/scans/service.js';

export const silentLog = pino({ level: 'silent' });

/** A reputation provider with a fixed answer. */
export function fakeReputation(result: ReputationResult | ((url: URL) => ReputationResult), critical = true): ReputationProvider {
  return {
    id: 'fake',
    label: 'Fake reputation',
    critical,
    check: async (url) => (typeof result === 'function' ? result(url) : result),
  };
}

export const clean: ReputationResult = { status: 'completed', matches: [] };

/** Page fetcher returning canned results keyed by hostname. Unknown hosts look like a plain, harmless page. */
export function fakeFetcher(pages: Record<string, Partial<SafeFetchResult>> = {}): PageFetcher & { calls: URL[] } {
  const calls: URL[] = [];
  return {
    calls,
    async fetch(url: URL, _o: SafeFetchOptions): Promise<SafeFetchResult> {
      calls.push(url);
      const page = pages[url.hostname] ?? {};
      return {
        hops: [{ url: url.href, hostname: url.hostname, status: 200, crossDomain: false }],
        finalUrl: url,
        status: 200,
        contentType: 'text/html',
        body: '<html><head><title>Welcome</title></head><body>Hello</body></html>',
        truncated: false,
        ...page,
      };
    },
  };
}

export function harness(overrides: Overrides = {}, config: Partial<Record<keyof Config, string>> = {}) {
  const deps = buildDeps(testConfig(config), silentLog, {
    fetcher: fakeFetcher(),
    reputationProviders: [fakeReputation(clean)],
    registration: null,
    ...overrides,
  });
  return { deps, app: createApp(deps) };
}

export const as = (uid: string) => ({ authorization: `Bearer dev:${uid}` });
