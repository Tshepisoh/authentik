import { createServer, request as httpRequest, type IncomingMessage, type Server } from 'node:http';
import { connect, type AddressInfo, type Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { ALLOWED_PORTS } from '@authentik/shared';
import { resolveAndCheck, type Resolver } from '@authentik/shared/net';

export interface EgressProxyOptions {
  /** Called for every refused destination. */
  onBlocked: (hostname: string, code: string) => void;
  /** Called if the proxy stops unexpectedly — the session must be torn down. */
  onFailure: (reason: string) => void;
  /** Test hook. Production uses system DNS through the shared policy. */
  resolver?: Resolver;
  /** Maximum concurrent upstream connections for this session. */
  maxConnections?: number;
}

export interface EgressProxy {
  port: number;
  /** Hostnames the proxy has seen requests for (used for the isolation self-test). */
  seen: Set<string>;
  close(): Promise<void>;
}

/** Hostname the worker requests at startup to prove the browser's traffic flows through this proxy. */
export const ISOLATION_PROBE_HOST = 'isolation-probe.authentik.invalid';

/**
 * A per-session forward proxy and the browser's *only* route to the network.
 *
 * Chromium is launched with `--proxy-server` pointing here (and loopback
 * bypass disabled), so every request — HTTP, HTTPS via CONNECT, WebSocket —
 * names its destination to us first. We resolve it, require every address to
 * be public, and connect to the address we validated. DNS rebinding,
 * private ranges, cloud metadata and non-web ports are all refused.
 *
 * Defence in depth: the container's network should *also* deny egress to
 * private ranges, so that a browser escaping this proxy still can't reach them.
 */
export async function startEgressProxy(opts: EgressProxyOptions): Promise<EgressProxy> {
  const seen = new Set<string>();
  const sockets = new Set<Socket | Duplex>();
  const maxConnections = opts.maxConnections ?? 64;
  let closing = false;

  const check = async (rawHost: string, port: number) => {
    let hostname: string;
    try {
      // Canonicalise (e.g. "0x7f.1" → "127.0.0.1", strip brackets) exactly as a URL parser would.
      hostname = new URL(`http://${rawHost.includes(':') && !rawHost.startsWith('[') ? `[${rawHost}]` : rawHost}/`).hostname;
    } catch {
      return { ok: false as const, hostname: rawHost, code: 'invalid_host' };
    }
    const bare = hostname.replace(/^\[|\]$/g, '');
    seen.add(bare);
    if (bare === ISOLATION_PROBE_HOST) return { ok: false as const, hostname: bare, code: 'probe', silent: true };
    if (!ALLOWED_PORTS.has(port)) return { ok: false as const, hostname: bare, code: 'port_not_allowed' };
    if (sockets.size >= maxConnections) return { ok: false as const, hostname: bare, code: 'connection_limit' };
    const result = await resolveAndCheck(bare, opts.resolver);
    // A name that doesn't resolve is unreachable, not a policy violation: fail the request quietly.
    if (!result.allowed && result.code === 'dns_failure') return { ok: false as const, hostname: bare, code: result.code, silent: true };
    if (!result.allowed) return { ok: false as const, hostname: bare, code: result.code };
    return { ok: true as const, hostname: bare, address: result.addresses[0]!.address };
  };

  const track = <T extends Socket | Duplex>(s: T): T => {
    sockets.add(s);
    s.once('close', () => sockets.delete(s));
    return s;
  };

  const server: Server = createServer(async (req, res) => {
    // Plain-HTTP proxying: the request line carries an absolute URL.
    let target: URL;
    try {
      target = new URL(req.url ?? '');
      if (target.protocol !== 'http:') throw new Error('scheme');
    } catch {
      res.writeHead(400).end();
      return;
    }
    const port = target.port ? Number(target.port) : 80;
    const verdict = await check(target.hostname, port);
    if (!verdict.ok) {
      if (!('silent' in verdict)) opts.onBlocked(verdict.hostname, verdict.code);
      if (verdict.code === 'dns_failure') res.writeHead(502).end();
      else res.writeHead(403, { 'content-type': 'text/plain' }).end('Blocked by Authentik Sandbox policy');
      return;
    }
    const headers = stripHopHeaders(req);
    const upstream = httpRequest({
      host: verdict.address,
      port,
      method: req.method,
      path: `${target.pathname}${target.search}`,
      headers: { ...headers, host: target.host },
      timeout: 30_000,
    });
    upstream.on('socket', (s) => track(s));
    upstream.on('response', (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.pipe(res);
    });
    upstream.on('timeout', () => upstream.destroy());
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502).end();
      else res.destroy();
    });
    req.pipe(upstream);
  });

  // HTTPS (and WSS): the browser asks us to open a raw tunnel to host:port.
  server.on('connect', async (req: IncomingMessage, client: Duplex, head: Buffer) => {
    track(client);
    client.on('error', () => client.destroy());
    const m = /^(\[[^\]]+\]|[^:]+):(\d{1,5})$/.exec(req.url ?? '');
    if (!m) {
      client.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }
    const verdict = await check(m[1]!, Number(m[2]));
    if (!verdict.ok) {
      if (!('silent' in verdict)) opts.onBlocked(verdict.hostname, verdict.code);
      client.end(verdict.code === 'dns_failure' ? 'HTTP/1.1 502 Bad Gateway\r\n\r\n' : 'HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }
    const upstream = track(connect({ host: verdict.address, port: Number(m[2]), timeout: 30_000 }));
    upstream.once('connect', () => {
      upstream.setTimeout(0);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('timeout', () => upstream.destroy());
    upstream.on('error', () => client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'));
    client.on('close', () => upstream.destroy());
  });

  server.on('clientError', (_err, socket) => socket.destroy());

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    // Loopback only: the proxy is reachable from this worker's browser and nothing else.
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

  server.on('close', () => {
    if (!closing) opts.onFailure('egress proxy stopped unexpectedly');
  });
  server.on('error', (err) => opts.onFailure(`egress proxy error: ${err.message}`));

  return {
    port: (server.address() as AddressInfo).port,
    seen,
    async close() {
      closing = true;
      for (const s of sockets) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

const HOP_HEADERS = new Set([
  'proxy-connection', 'proxy-authorization', 'connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'te', 'trailer',
]);

function stripHopHeaders(req: IncomingMessage) {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v !== undefined && !HOP_HEADERS.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}
