import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import request from 'supertest';
import WebSocket, { WebSocketServer } from 'ws';
import type { Report, SandboxSessionResponse } from '@authentik/shared';
import { buildDeps } from '../container.js';
import { testConfig } from '../config.js';
import { createHttpServer } from '../server.js';
import type { SandboxWorker, WorkerSessionSpec } from '../sandbox-control/workers/client.js';
import { as, clean, fakeFetcher, fakeReputation, silentLog } from './harness.js';

/** Stands in for the isolated browser worker: records calls and exposes the worker end of each stream. */
class FakeWorker implements SandboxWorker {
  readonly configured = true;
  created: WorkerSessionSpec[] = [];
  closed: string[] = [];
  streams = new Map<string, WebSocket>();
  failCreate = false;
  private wss!: WebSocketServer;
  private port = 0;

  async start() {
    this.wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise<void>((r) => this.wss.once('listening', () => r()));
    this.port = (this.wss.address() as AddressInfo).port;
    this.wss.on('connection', (ws, req) => {
      const id = /\/sessions\/([^/]+)\/stream/.exec(req.url ?? '')![1]!;
      this.streams.set(id, ws);
    });
  }
  stop() {
    return new Promise<void>((r) => this.wss.close(() => r()));
  }
  async createSession(spec: WorkerSessionSpec) {
    if (this.failCreate) throw new Error('isolation not established');
    this.created.push(spec);
  }
  async closeSession(id: string) {
    this.closed.push(id);
    this.streams.get(id)?.close();
  }
  openStream(id: string) {
    return new WebSocket(`ws://127.0.0.1:${this.port}/sessions/${id}/stream`);
  }
}

const tick = (ms = 50) => new Promise((r) => setTimeout(r, ms));
const until = async (fn: () => boolean, ms = 2000) => {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error('condition not met');
    await tick(10);
  }
};

let worker: FakeWorker;
let server: Server;
let base: string;
let deps: ReturnType<typeof buildDeps>;

async function setup(reputation = fakeReputation(clean)) {
  worker = new FakeWorker();
  await worker.start();
  deps = buildDeps(testConfig(), silentLog, { worker, fetcher: fakeFetcher(), reputationProviders: [reputation], registration: null });
  server = createHttpServer(deps);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function viewer(session: SandboxSessionResponse, token = session.viewToken) {
  const ws = new WebSocket(`ws://${base}${session.streamPath}`, { headers: { authorization: `Bearer ${token}` } });
  const received: Record<string, unknown>[] = [];
  let closeCode: number | null = null;
  ws.on('message', (m) => received.push(JSON.parse(m.toString())));
  ws.on('close', (code) => (closeCode = code));
  return { ws, received, closeCode: () => closeCode, open: () => new Promise((r) => ws.once('open', r)) };
}

describe('sandbox lifecycle', () => {
  beforeEach(() => setup());
  afterEach(async () => {
    await deps.shutdown();
    await new Promise<void>((r) => server.close(() => r()));
    await worker.stop();
  });

  it('runs a session end to end and produces a report', async () => {
    const created = await request(server).post('/v1/sandbox/sessions').set(as('sbx')).send({ url: 'https://example.com/?ref=abc' }).expect(201);
    const session = created.body as SandboxSessionResponse;
    expect(session.state).toBe('active');
    expect(worker.created[0]!.url).toBe('https://example.com/?ref=abc'); // only the worker sees the full URL
    await until(() => worker.streams.has(session.sessionId));
    const upstream = worker.streams.get(session.sessionId)!;
    const fromViewer: Record<string, unknown>[] = [];
    upstream.on('message', (m) => fromViewer.push(JSON.parse(m.toString())));

    // A wrong token is refused.
    const intruder = viewer(session, 'not-the-token');
    await until(() => intruder.closeCode() !== null);
    expect(intruder.closeCode()).toBe(4401);

    const v = viewer(session);
    await v.open();
    await tick();

    upstream.send(JSON.stringify({ type: 'frame', data: 'AAAA', width: 390, height: 844 }));
    upstream.send(JSON.stringify({ type: 'navigated', url: 'https://example.com/account?session=SECRET', title: 'Example' }));
    upstream.send(JSON.stringify({ type: 'nonsense' }));
    await until(() => v.received.length >= 2);
    expect(v.received.map((m) => m.type)).toEqual(['frame', 'navigated']);
    expect(JSON.stringify(v.received)).not.toContain('SECRET');

    v.ws.send(JSON.stringify({ type: 'tap', x: 10, y: 20 }));
    v.ws.send(JSON.stringify({ type: 'navigate', url: 'http://169.254.169.254/latest' }));
    v.ws.send(JSON.stringify({ type: 'evaluate', script: 'alert(1)' }));
    await until(() => fromViewer.length >= 1 && v.received.length >= 3);
    await tick();
    expect(fromViewer).toEqual([{ type: 'tap', x: 10, y: 20 }]);
    expect(v.received[2]).toMatchObject({ type: 'event', event: { type: 'blocked_destination' } }); // the viewer is told…

    // …but only what the *site* does counts against it.
    upstream.send(JSON.stringify({ type: 'event', event: { type: 'blocked_destination', at: new Date().toISOString(), target: '10.0.0.5', severity: 'critical' } }));
    await until(() => v.received.length >= 4);

    const closed = await request(server).delete(`/v1/sandbox/sessions/${session.sessionId}`).set(as('sbx')).expect(200);
    const report = closed.body as Report;
    expect(report.type).toBe('sandbox_session');
    expect(report.verdict).toBe('high_risk');
    const blocked = report.assessment.findings.find((f) => f.code === 'blocked_destination');
    expect(blocked?.data?.count).toBe(1);
    expect(blocked?.reason).toContain('10.0.0.5');
    expect(report.relatedReportId).toBe(session.scan.id);
    expect(report.sandbox!.visitedHosts).toContain('example.com');
    expect(worker.closed).toContain(session.sessionId);
    await until(() => v.closeCode() !== null);

    // Credentials are revoked: reconnecting with the same token fails.
    const again = viewer(session);
    await until(() => again.closeCode() !== null);
    expect(again.closeCode()).toBe(4401);

    // Closing twice returns the same report.
    const twice = await request(server).delete(`/v1/sandbox/sessions/${session.sessionId}`).set(as('sbx')).expect(200);
    expect(twice.body.id).toBe(report.id);
    await request(server).get(`/v1/sandbox/sessions/${session.sessionId}`).set(as('other')).expect(404);
  });

  it('accepts the same-origin Origin header React Native on Android sends, and rejects foreign origins', async () => {
    const session = (await request(server).post('/v1/sandbox/sessions').set(as('sbx')).send({ url: 'https://example.com' }).expect(201)).body as SandboxSessionResponse;
    const connect = (origin: string) =>
      new Promise<'open' | 'rejected'>((resolve) => {
        const ws = new WebSocket(`ws://${base}${session.streamPath}`, { headers: { authorization: `Bearer ${session.viewToken}`, origin } });
        ws.once('open', () => {
          ws.close();
          resolve('open');
        });
        ws.once('unexpected-response', () => resolve('rejected'));
        ws.once('error', () => resolve('rejected'));
      });
    expect(await connect(`http://${base}`)).toBe('open');
    expect(await connect('https://evil.example')).toBe('rejected');
  });

  it('refuses to open the site when isolation cannot be established', async () => {
    worker.failCreate = true;
    const res = await request(server).post('/v1/sandbox/sessions').set(as('sbx')).send({ url: 'https://example.com' }).expect(503);
    expect(res.body.error.code).toBe('isolation_unavailable');
    const sessions = await deps.store.sandboxSessions.listByUser('sbx');
    expect(sessions[0]).toMatchObject({ state: 'failed', viewTokenHash: '' });
  });

  it('stops immediately on an isolation failure', async () => {
    const session = (await request(server).post('/v1/sandbox/sessions').set(as('sbx')).send({ url: 'https://example.com' }).expect(201)).body;
    await until(() => worker.streams.has(session.sessionId));
    worker.streams.get(session.sessionId)!.send(JSON.stringify({ type: 'event', event: { type: 'isolation_failure', at: new Date().toISOString(), severity: 'critical', detail: 'egress proxy down' } }));
    await until(() => worker.closed.includes(session.sessionId));
    await tick(100);
    const doc = await deps.store.sandboxSessions.get(session.sessionId);
    expect(doc).toMatchObject({ state: 'failed', endReason: 'isolation_failure' });
  });

  it('limits concurrent sessions per user', async () => {
    await request(server).post('/v1/sandbox/sessions').set(as('busy')).send({ url: 'https://example.com' }).expect(201);
    const res = await request(server).post('/v1/sandbox/sessions').set(as('busy')).send({ url: 'https://example.org' }).expect(409);
    expect(res.body.error.code).toBe('sandbox_session_limit');
  });

  it('refuses blocked targets without contacting the worker', async () => {
    await request(server).post('/v1/sandbox/sessions').set(as('sbx')).send({ url: 'http://10.1.2.3/' }).expect(403);
    expect(worker.created).toHaveLength(0);
  });
});

describe('sandbox risk acknowledgement', () => {
  beforeEach(() => setup(fakeReputation({ status: 'completed', matches: [{ threatType: 'SOCIAL_ENGINEERING' }] })));
  afterEach(async () => {
    await deps.shutdown();
    await new Promise<void>((r) => server.close(() => r()));
    await worker.stop();
  });

  it('requires explicit acknowledgement for high-risk targets', async () => {
    const res = await request(server).post('/v1/sandbox/sessions').set(as('sbx')).send({ url: 'https://phish.example.net' }).expect(409);
    expect(res.body.error.code).toBe('risk_acknowledgement_required');
    await request(server).post('/v1/sandbox/sessions').set(as('sbx')).send({ url: 'https://phish.example.net', acknowledgeRisk: true }).expect(201);
  });
});
