import type { LookupFunction } from 'node:net';
import { Agent, fetch, type Dispatcher } from 'undici';
import {
  checkStaticDestination,
  normalizeTargetUrl,
  redactUrl,
  registrableDomain,
  type DestinationCheck,
  type RedirectHop,
} from '@authentik/shared';
import { createSafeLookup, DestinationBlockedError } from '@authentik/shared/net';

export interface SafeFetchOptions {
  timeoutMs: number;
  maxBytes: number;
  maxRedirects: number;
  accept?: string;
}

export interface SafeFetchResult {
  hops: RedirectHop[];
  /** The last URL we reached (full, in memory only — never persist it unredacted). */
  finalUrl: URL;
  status: number | null;
  contentType: string | null;
  /** Decoded text body for text-like responses, capped at `maxBytes`. */
  body: string | null;
  truncated: boolean;
  /** Set when a hop violated the destination policy. Fetching stopped there. */
  blocked?: { code: string; message: string; hostname: string };
  /** Set when the network failed (timeout, TLS, refused). */
  error?: string;
}

export interface SafeFetcherDeps {
  /** Override for tests. Production always uses the validating lookup. */
  lookup?: LookupFunction;
  /** Override for tests. Production always uses the shared static policy. */
  checkStatic?: (url: URL) => DestinationCheck;
  userAgent?: string;
}

/**
 * Fetches untrusted URLs without letting them reach internal infrastructure.
 *
 * - Every hop (including each redirect) is checked against the static policy.
 * - DNS resolution happens inside the connection's `lookup`, which refuses any
 *   non-public address and connects to the exact address it validated.
 * - Redirects are followed manually so each Location is re-validated.
 * - No cookies, no credentials, bounded time and bounded body size.
 */
export class SafeFetcher {
  private readonly dispatcher: Dispatcher;
  private readonly checkStatic: (url: URL) => DestinationCheck;
  private readonly userAgent: string;

  constructor(deps: SafeFetcherDeps = {}) {
    this.dispatcher = new Agent({
      connect: { lookup: deps.lookup ?? createSafeLookup(), timeout: 5000 },
      headersTimeout: 8000,
      bodyTimeout: 8000,
      maxRedirections: 0,
    } as Agent.Options);
    this.checkStatic = deps.checkStatic ?? checkStaticDestination;
    this.userAgent = deps.userAgent ?? 'AuthentikScanner/0.1 (+https://authentik.app/scanner)';
  }

  async fetch(start: URL, options: SafeFetchOptions): Promise<SafeFetchResult> {
    const hops: RedirectHop[] = [];
    const startDomain = registrableDomain(start.hostname);
    let current = start;
    const deadline = AbortSignal.timeout(options.timeoutMs);

    for (let i = 0; i <= options.maxRedirects; i++) {
      const policy = this.checkStatic(current);
      if (!policy.allowed) {
        return this.result(hops, current, { blocked: { code: policy.code, message: policy.message, hostname: current.hostname } });
      }

      let response: Awaited<ReturnType<typeof fetch>>;
      try {
        response = await fetch(current, {
          method: 'GET',
          redirect: 'manual',
          dispatcher: this.dispatcher,
          signal: deadline,
          headers: {
            'user-agent': this.userAgent,
            accept: options.accept ?? 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
            'accept-language': 'en-ZA,en;q=0.8',
          },
        });
      } catch (err) {
        const blocked = findBlocked(err);
        // A name that doesn't resolve is unreachable, not a policy violation.
        if (blocked?.code === 'dns_failure') {
          return this.result(hops, current, { error: 'The website name could not be resolved' });
        }
        if (blocked) {
          return this.result(hops, current, { blocked: { code: blocked.code, message: blocked.message, hostname: blocked.hostname } });
        }
        return this.result(hops, current, { error: describeNetworkError(err) });
      }

      hops.push({
        url: redactUrl(current),
        hostname: current.hostname,
        status: response.status,
        crossDomain: registrableDomain(current.hostname) !== startDomain,
      });

      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location) {
        await response.body?.cancel().catch(() => undefined);
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          return this.result(hops, current, { status: response.status, error: 'Invalid redirect location' });
        }
        const normalized = normalizeTargetUrl(next.href);
        if (!normalized.ok) {
          return this.result(hops, current, {
            status: response.status,
            blocked: { code: `redirect_${normalized.code}`, message: 'The site redirected to an address that cannot be followed.', hostname: next.hostname },
          });
        }
        current = normalized.url;
        continue;
      }

      const contentType = response.headers.get('content-type');
      const { body, truncated } = isTextual(contentType)
        ? await readCapped(response, options.maxBytes)
        : (await response.body?.cancel().catch(() => undefined), { body: null, truncated: false });
      return { hops, finalUrl: current, status: response.status, contentType, body, truncated };
    }

    return this.result(hops, current, { error: `Stopped after ${options.maxRedirects} redirects` });
  }

  private result(hops: RedirectHop[], finalUrl: URL, extra: Partial<SafeFetchResult>): SafeFetchResult {
    return { hops, finalUrl, status: null, contentType: null, body: null, truncated: false, ...extra };
  }

  async close() {
    await this.dispatcher.close();
  }
}

function isTextual(contentType: string | null) {
  // Includes structured-suffix JSON such as application/rdap+json.
  return !!contentType && /^(text\/|application\/(xhtml\+xml|json|xml|[\w.-]+\+json))/i.test(contentType);
}

async function readCapped(response: Response | Awaited<ReturnType<typeof fetch>>, maxBytes: number) {
  const reader = response.body?.getReader();
  if (!reader) return { body: null, truncated: false };
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - size));
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  return { body: Buffer.concat(chunks).toString('utf8'), truncated };
}

function findBlocked(err: unknown): DestinationBlockedError | null {
  let e: unknown = err;
  for (let depth = 0; e && depth < 5; depth++) {
    if (e instanceof DestinationBlockedError) return e;
    e = (e as { cause?: unknown }).cause;
  }
  return null;
}

function describeNetworkError(err: unknown): string {
  const e = err as { name?: string; cause?: { code?: string } };
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return 'The site took too long to respond';
  const code = e?.cause?.code;
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'The website name could not be resolved';
  if (code === 'ECONNREFUSED') return 'The site refused the connection';
  if (code && /CERT|SSL|TLS/i.test(code)) return 'The site presented an invalid security certificate';
  return 'The site could not be reached';
}
