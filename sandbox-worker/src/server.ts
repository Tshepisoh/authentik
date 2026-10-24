import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { z } from 'zod';
import { checkStaticDestination, normalizeTargetUrl } from '@authentik/shared';
import { CapacityError, IsolationError, type SessionManager } from './lifecycle/manager.js';

const specSchema = z.object({
  sessionId: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/),
  url: z.string().max(2048),
  viewport: z.object({ width: z.number().int().min(240).max(1440), height: z.number().int().min(320).max(3200) }),
  ttlSeconds: z.number().int().min(30).max(3600),
});

const SESSION_PATH = /^\/sessions\/([A-Za-z0-9_-]{8,64})$/;
const EXTRACT_PATH = /^\/sessions\/([A-Za-z0-9_-]{8,64})\/extract$/;
const STREAM_PATH =/^\/sessions\/([A-Za-z0-9_-]{8,64})\/stream$/;

/**
 * Internal control API. Only the Authentik control plane can reach it (private
 * network) and it requires the shared secret. It exposes nothing but session
 * lifecycle — no data, no file access, no arbitrary script execution.
 */
export function createWorkerServer(manager: SessionManager, secret: string) {
  const authorized = (req: IncomingMessage) => {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization ?? '');
    if (!m || !secret) return false;
    const a = Buffer.from(m[1]!);
    const b = Buffer.from(secret);
    return a.length === b.length && timingSafeEqual(a, b);
  };
  const json = (res: ServerResponse, status: number, body?: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' }).end(body === undefined ? undefined : JSON.stringify(body));
  };

  const server = createServer(async (req, res) => {
    const path = (req.url ?? '').split('?')[0]!;
    if (req.method === 'GET' && path === '/health') return json(res, 200, { status: 'ok', active: manager.size, capacity: manager.capacity });
    if (!authorized(req)) return json(res, 401, { error: 'unauthorized' });

    if (req.method === 'POST' && path === '/sessions') {
      let body: unknown;
      try {
        body = JSON.parse(await readBody(req, 8 * 1024));
      } catch {
        return json(res, 400, { error: 'invalid_body' });
      }
      const spec = specSchema.safeParse(body);
      if (!spec.success) return json(res, 400, { error: 'invalid_spec' });
      // Re-validate the target: the worker trusts no one's URL, including the control plane's.
      const target = normalizeTargetUrl(spec.data.url);
      if (!target.ok || !checkStaticDestination(target.url).allowed) return json(res, 422, { error: 'target_not_permitted' });
      try {
        await manager.create({ ...spec.data, url: target.url.href });
        return json(res, 201, { sessionId: spec.data.sessionId });
      } catch (err) {
        if (err instanceof CapacityError) return json(res, 503, { error: 'capacity' });
        if (err instanceof IsolationError) return json(res, 503, { error: 'isolation_unavailable' });
        return json(res, 500, { error: 'internal' });
      }
    }

    // One-shot read of payment details from a URL, in a throwaway isolated browser.
    if (req.method === 'POST' && path === '/extract') {
      let body: { url?: unknown };
      try {
        body = JSON.parse(await readBody(req, 8 * 1024));
      } catch {
        return json(res, 400, { error: 'invalid_body' });
      }
      const target = normalizeTargetUrl(typeof body.url === 'string' ? body.url : '');
      if (!target.ok || !checkStaticDestination(target.url).allowed) return json(res, 422, { error: 'target_not_permitted' });
      try {
        return json(res, 200, await manager.extractFromUrl(target.url.href));
      } catch (err) {
        if (err instanceof CapacityError) return json(res, 503, { error: 'capacity' });
        if (err instanceof IsolationError) return json(res, 503, { error: 'isolation_unavailable' });
        return json(res, 502, { error: 'page_unreadable' });
      }
    }

    const ext = EXTRACT_PATH.exec(path);
    if (req.method === 'POST' && ext) {
      try {
        const result = await manager.extractFromSession(ext[1]!);
        return result ? json(res, 200, result) : json(res, 404, { error: 'no_such_session' });
      } catch {
        return json(res, 502, { error: 'page_unreadable' });
      }
    }

    const del = SESSION_PATH.exec(path);
    if (req.method === 'DELETE' && del) {
      await manager.close(del[1]!, 'closed_by_control_plane');
      return json(res, 204);
    }
    return json(res, 404, { error: 'not_found' });
  });

  const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 });
  server.on('upgrade', (req, socket, head) => {
    const m = STREAM_PATH.exec((req.url ?? '').split('?')[0]!);
    if (!m || !authorized(req)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      if (!manager.attach(m[1]!, ws)) ws.close(4404, 'no such session');
    });
  });

  return server;
}

function readBody(req: IncomingMessage, max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > max) {
        reject(new Error('too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
