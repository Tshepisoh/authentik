import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo, LookupFunction } from 'node:net';
import { checkStaticDestination } from '@authentik/shared';
import { createSafeLookup } from '@authentik/shared/net';
import { SafeFetcher } from './index.js';

/**
 * A local server stands in for "the internet". The fetcher is told that
 * `public.test` resolves to it (and allowed on its port); everything else goes
 * through the real policy — so these tests exercise the real blocking paths.
 */
let server: Server;
let port: number;

beforeAll(async () => {
  server = createServer((req, res) => {
    const to = (loc: string) => res.writeHead(302, { location: loc }).end();
    if (req.url === '/to-metadata') return to('http://169.254.169.254/latest/meta-data/');
    if (req.url === '/to-localhost') return to('http://localhost/admin');
    if (req.url === '/to-rebind') return to(`http://rebind.test/`);
    if (req.url === '/to-javascript') return to('javascript:alert(1)');
    if (req.url === '/loop') return to('/loop');
    if (req.url === '/big') return res.writeHead(200, { 'content-type': 'text/html' }).end('x'.repeat(50_000));
    if (req.url === '/hop') return to('/final');
    if (req.url === '/final') return res.writeHead(200, { 'content-type': 'text/html' }).end('<title>Done</title>');
    if (req.url === '/rdap') return res.writeHead(200, { 'content-type': 'application/rdap+json' }).end('{"events":[]}');
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

function fetcher() {
  const strict = createSafeLookup(async (host) => (host === 'rebind.test' ? [{ address: '10.0.0.7', family: 4 }] : []));
  const lookup: LookupFunction = (host, opts, cb) => {
    if (host === 'public.test') {
      if (typeof opts === 'object' && opts.all) return (cb as unknown as (e: null, a: unknown[]) => void)(null, [{ address: '127.0.0.1', family: 4 }]);
      return cb(null, '127.0.0.1', 4);
    }
    return strict(host, opts, cb);
  };
  return new SafeFetcher({
    lookup,
    checkStatic: (u) => (u.hostname === 'public.test' ? { allowed: true } : checkStaticDestination(u)),
  });
}
const opts = { timeoutMs: 3000, maxBytes: 10_000, maxRedirects: 3 };
const at = (path: string) => new URL(`http://public.test:${port}${path}`);

describe('SafeFetcher', () => {
  it('follows same-site redirects and records hops', async () => {
    const r = await fetcher().fetch(at('/hop'), opts);
    expect(r.status).toBe(200);
    expect(r.hops.map((h) => h.status)).toEqual([302, 200]);
    expect(r.body).toContain('Done');
  });

  it.each([
    ['/to-metadata', 'non_public_address'],
    ['/to-localhost', 'blocked_hostname'],
    ['/to-rebind', 'non_public_address'],
    ['/to-javascript', 'redirect_unsupported_scheme'],
  ])('stops at a redirect %s (%s)', async (path, code) => {
    const r = await fetcher().fetch(at(path), opts);
    expect(r.blocked?.code).toBe(code);
  });

  it('refuses a private IP literal target outright', async () => {
    const r = await new SafeFetcher().fetch(new URL(`http://127.0.0.1:${port}/final`), opts);
    expect(r.blocked?.code).toBe('port_not_allowed');
    const r2 = await new SafeFetcher().fetch(new URL('http://127.0.0.1/final'), opts);
    expect(r2.blocked?.code).toBe('non_public_address');
  });

  it('reports a name that does not resolve as unreachable, not as a blocked destination', async () => {
    const r = await fetcher().fetch(new URL('http://does-not-exist.test/'), opts);
    expect(r.blocked).toBeUndefined();
    expect(r.error).toMatch(/could not be resolved/);
  });

  it('reads structured-suffix JSON bodies such as RDAP responses', async () => {
    const r = await fetcher().fetch(at('/rdap'), opts);
    expect(r.body).toBe('{"events":[]}');
  });

  it('bounds redirect loops and body size', async () => {
    const loop = await fetcher().fetch(at('/loop'), opts);
    expect(loop.error).toMatch(/redirects/);
    const big = await fetcher().fetch(at('/big'), opts);
    expect(big.truncated).toBe(true);
    expect(big.body!.length).toBe(10_000);
  });
});
