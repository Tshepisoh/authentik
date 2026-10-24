import { getDomain, getPublicSuffix } from 'tldts';

export const MAX_URL_LENGTH = 2048;

export type UrlRejection =
  | 'empty'
  | 'too_long'
  | 'unparseable'
  | 'unsupported_scheme'
  | 'missing_host';

export type NormalizeResult =
  | {
      ok: true;
      url: URL;
      /** The input contained `user:pass@` — a classic way to disguise the real host. */
      hadCredentials: boolean;
      /** The scheme was missing and `https://` was assumed. */
      schemeAssumed: boolean;
    }
  | { ok: false; code: UrlRejection; message: string };

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:/i;

/**
 * Parses user input into an http(s) URL. Credentials are stripped (and
 * reported) so later stages always look at the real destination host.
 */
export function normalizeTargetUrl(input: string): NormalizeResult {
  const raw = input.trim();
  if (!raw) return { ok: false, code: 'empty', message: 'Enter a website address.' };
  if (raw.length > MAX_URL_LENGTH) {
    return { ok: false, code: 'too_long', message: 'That address is too long to scan.' };
  }

  // "takealot.com/deals" → assume https. Anything with an explicit scheme keeps it.
  const schemeAssumed = !SCHEME_RE.test(raw) || /^[^/:]+:\d+(\/|$)/.test(raw);
  const candidate = schemeAssumed ? `https://${raw}` : raw;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { ok: false, code: 'unparseable', message: 'That does not look like a website address.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return {
      ok: false,
      code: 'unsupported_scheme',
      message: 'Only http and https website addresses can be checked.',
    };
  }
  if (!url.hostname) {
    return { ok: false, code: 'missing_host', message: 'That address has no website name.' };
  }

  const hadCredentials = url.username !== '' || url.password !== '';
  url.username = '';
  url.password = '';
  url.hash = '';
  // Trailing dot is the same host; normalise it away so comparisons are stable.
  if (url.hostname.endsWith('.')) url.hostname = url.hostname.replace(/\.+$/, '');

  return { ok: true, url, hadCredentials, schemeAssumed };
}

/** The registrable domain ("eTLD+1"), e.g. `shop.takealot.com` → `takealot.com`. */
export function registrableDomain(hostname: string): string | null {
  return getDomain(hostname, { allowPrivateDomains: true }) ?? null;
}

export function publicSuffix(hostname: string): string | null {
  return getPublicSuffix(hostname, { allowPrivateDomains: true }) ?? null;
}

/** True when `hostname` is `domain` or a subdomain of it. */
export function isSameOrSubdomain(hostname: string, domain: string): boolean {
  const h = hostname.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

const TOKENISH_SEGMENT = /^[A-Za-z0-9_\-~.%]{24,}$/;
const DIGITS_ONLY = /^\d{6,}$/;

/**
 * A URL as it is safe to store or show: no credentials, no fragment, query
 * values replaced, and path segments that look like tokens or identifiers
 * replaced. Keys are kept because they help explain what a link does.
 */
export function redactUrl(input: URL | string): string {
  let url: URL;
  try {
    url = typeof input === 'string' ? new URL(input) : new URL(input.href);
  } catch {
    return '[unparseable url]';
  }
  const path = url.pathname
    .split('/')
    .map((seg) => (TOKENISH_SEGMENT.test(seg) || DIGITS_ONLY.test(seg) ? '[redacted]' : seg))
    .join('/');

  const keys = [...new Set([...url.searchParams.keys()])];
  const query = keys.length
    ? `?${keys
        .slice(0, 10)
        .map((k) => `${encodeURIComponent(k.slice(0, 40))}=[redacted]`)
        .join('&')}${keys.length > 10 ? '&…' : ''}`
    : '';

  const port = url.port ? `:${url.port}` : '';
  return `${url.protocol}//${url.hostname}${port}${path}${query}`;
}
