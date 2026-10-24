import { afterEach, describe, expect, it } from 'vitest';
import { connect } from 'node:net';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { pino } from 'pino';
import WebSocket from 'ws';
import { ISOLATION_PROBE_HOST, startEgressProxy, type EgressProxy } from './network-policy/egress-proxy.js';
import { IsolationError, CapacityError, SessionManager } from './lifecycle/manager.js';
import { createWorkerServer } from './server.js';

const log = pino({ level: 'silent' });

/** Sends a raw CONNECT and returns the proxy's status line. */
function tunnel(proxy: EgressProxy, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(proxy.port, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    s.once('data', (d) => {
      resolve(d.toString().split('\r\n')[0]!);
      s.destroy();
    });
    s.once('error', reject);
  });
}

function httpVia(proxy: EgressProxy, url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: proxy.port, path: url, method: 'GET', headers: { host: new URL(url).host } }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', reject);
    req.end();
  });
}

describe('egress proxy', () => {
  let proxy: EgressProxy;
  const blocked: [string, string][] = [];
  afterEach(async () => {
    await proxy?.close();
    blocked.length = 0;
  });

  const start = () =>
    startEgressProxy({
      onBlocked: (h, c) => blocked.push([h, c]),
      onFailure: () => undefined,
      resolver: async (host) => (host === 'rebind.example' ? [{ address: '93.184.216.34', family: 4 }, { address: '192.168.0.10', family: 4 }] : [{ address: '10.9.9.9', family: 4 }]),
    });

  it.each([
    ['127.0.0.1:443', 'non_public_address'],
    ['[::1]:443', 'non_public_address'],
    ['169.254.169.254:443', 'non_public_address'],
    ['0x7f.1:443', 'non_public_address'],
    ['metadata.google.internal:443', 'blocked_hostname'],
    ['rebind.example:443', 'non_public_address'],
    ['internal-api.example:443', 'non_public_address'],
    ['example.com:22', 'port_not_allowed'],
  ])('refuses CONNECT %s (%s)', async (target, code) => {
    proxy = await start();
    expect(await tunnel(proxy, target)).toMatch(/403/);
    expect(blocked.at(-1)?.[1]).toBe(code);
  });

  it('refuses plain-HTTP requests to private destinations', async () => {
    proxy = await start();
    expect(await httpVia(proxy, 'http://localhost/admin')).toBe(403);
    expect(await httpVia(proxy, 'http://10.0.0.1/')).toBe(403);
    expect(blocked.map((b) => b[1])).toEqual(['blocked_hostname', 'non_public_address']);
  });

  it('treats a name that does not resolve as unreachable, not as a blocked destination', async () => {
    proxy = await startEgressProxy({
      onBlocked: (h, c) => blocked.push([h, c]),
      onFailure: () => undefined,
      resolver: async () => {
        throw new Error('ENOTFOUND');
      },
    });
    expect(await tunnel(proxy, 'ads.tracker.example:443')).toMatch(/502/);
    expect(blocked).toEqual([]);
  });

  it('answers the isolation probe without reporting it as a threat', async () => {
    proxy = await start();
    expect(await httpVia(proxy, `http://${ISOLATION_PROBE_HOST}/`)).toBe(403);
    expect(proxy.seen.has(ISOLATION_PROBE_HOST)).toBe(true);
    expect(blocked).toEqual([]);
  });

  it('reports an unexpected stop as an isolation failure', async () => {
    const failures: string[] = [];
    proxy = await startEgressProxy({ onBlocked: () => undefined, onFailure: (r) => failures.push(r) });
    await proxy.close();
    expect(failures).toEqual([]); // a deliberate close is not a failure
  });
});

function fakeBrowser(opts: { failStart?: boolean } = {}) {
  const made: { inputs: unknown[]; closed: boolean; emit: (m: never) => void }[] = [];
  return {
    made,
    createSession: (o: { emit: (m: never) => void }) => {
      const rec = { inputs: [] as unknown[], closed: false, emit: o.emit };
      made.push(rec);
      return {
        async start() {
          if (opts.failStart) throw new Error('self-test failed');
          o.emit({ type: 'event', event: { type: 'navigation', at: 'now', severity: 'info' } } as never);
        },
        async input(m: unknown) {
          rec.inputs.push(m);
        },
        async close() {
          rec.closed = true;
        },
      };
    },
  };
}
const spec = { sessionId: 'session-0001', url: 'https://example.com/', viewport: { width: 390, height: 844 }, ttlSeconds: 60 };

describe('session manager', () => {
  it('enforces capacity and unique ids', async () => {
    const fb = fakeBrowser();
    const m = new SessionManager({ maxSessions: 1, maxSessionSeconds: 60, chromiumSandbox: true, log, createSession: fb.createSession as never });
    await m.create(spec);
    await expect(m.create(spec)).rejects.toBeInstanceOf(CapacityError);
    await expect(m.create({ ...spec, sessionId: 'session-0002' })).rejects.toBeInstanceOf(CapacityError);
    await m.closeAll('test');
    expect(fb.made[0]!.closed).toBe(true);
    expect(m.size).toBe(0);
  });

  it('destroys the browser and refuses the session when isolation fails', async () => {
    const fb = fakeBrowser({ failStart: true });
    const m = new SessionManager({ maxSessions: 2, maxSessionSeconds: 60, chromiumSandbox: true, log, createSession: fb.createSession as never });
    await expect(m.create(spec)).rejects.toBeInstanceOf(IsolationError);
    expect(fb.made[0]!.closed).toBe(true);
    expect(m.size).toBe(0);
  });
});

describe('worker control API', () => {
  const secret = 'test-secret-0123456789abcdef';
  let close: () => Promise<void>;
  afterEach(() => close?.());

  async function serve() {
    const fb = fakeBrowser();
    const manager = new SessionManager({ maxSessions: 2, maxSessionSeconds: 60, chromiumSandbox: true, log, createSession: fb.createSession as never });
    const server = createWorkerServer(manager, secret);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const base = `127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = async () => {
      await manager.closeAll('test');
      await new Promise<void>((r) => server.close(() => r()));
    };
    return { base, fb, manager };
  }
  const post = (base: string, body: unknown, auth = secret) =>
    fetch(`http://${base}/sessions`, { method: 'POST', headers: { authorization: `Bearer ${auth}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  it('requires the shared secret', async () => {
    const { base } = await serve();
    expect((await post(base, spec, 'wrong-secret-0123456789abcdef')).status).toBe(401);
    expect((await fetch(`http://${base}/health`)).status).toBe(200);
  });

  it('re-validates the target URL itself', async () => {
    const { base, fb } = await serve();
    expect((await post(base, { ...spec, url: 'http://169.254.169.254/' })).status).toBe(422);
    expect((await post(base, { ...spec, url: 'file:///etc/passwd' })).status).toBe(422);
    expect(fb.made).toHaveLength(0);
  });

  it('creates a session, flushes early events to the stream and relays input', async () => {
    const { base, fb } = await serve();
    expect((await post(base, spec)).status).toBe(201);
    const ws = new WebSocket(`ws://${base}/sessions/${spec.sessionId}/stream`, { headers: { authorization: `Bearer ${secret}` } });
    const first = await new Promise<string>((r) => ws.once('message', (m) => r(m.toString())));
    expect(JSON.parse(first)).toMatchObject({ type: 'event', event: { type: 'navigation' } });
    ws.send(JSON.stringify({ type: 'tap', x: 1, y: 2 }));
    await new Promise((r) => setTimeout(r, 50));
    expect(fb.made[0]!.inputs).toEqual([{ type: 'tap', x: 1, y: 2 }]);

    const closed = new Promise<string>((r) => ws.on('message', (m) => r(m.toString())));
    await fetch(`http://${base}/sessions/${spec.sessionId}`, { method: 'DELETE', headers: { authorization: `Bearer ${secret}` } });
    expect(JSON.parse(await closed)).toEqual({ type: 'closed', reason: 'closed_by_control_plane' });
    expect(fb.made[0]!.closed).toBe(true);
  });
});
