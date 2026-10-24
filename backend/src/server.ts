import { createServer, type IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer } from 'ws';
import type { Deps } from './container.js';
import { createApp } from './app.js';

const STREAM_PATH = /^\/v1\/sandbox\/sessions\/([A-Za-z0-9_-]{8,64})\/stream$/;
const PROTOCOL_PREFIX = 'authentik.view.';

/** HTTP server plus the Sandbox stream WebSocket endpoint. */
export function createHttpServer(deps: Deps) {
  const server = createServer(createApp(deps));
  const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024, handleProtocols: (protocols) => (protocols.has('authentik.v1') ? 'authentik.v1' : false) });
  const allowedOrigins = new Set(deps.config.CORS_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean));

  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const path = (req.url ?? '').split('?')[0]!;
    const match = STREAM_PATH.exec(path);
    const origin = req.headers.origin;
    // Blocks cross-site WebSocket hijacking: a foreign web page may not open the stream. Allowed:
    // no Origin (iOS, Node), the API's own origin (React Native on Android sets this automatically),
    // and explicitly allow-listed origins.
    if (!match || (origin && !allowedOrigins.has(origin) && !isSameOrigin(origin, req.headers.host))) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const token = viewToken(req);
    wss.handleUpgrade(req, socket, head, (ws) => {
      if (!token) {
        ws.close(4401, 'unauthorized');
        return;
      }
      void deps.sandbox.attachViewer(match[1]!, token, ws);
    });
  });

  deps.sandbox.start();
  return server;
}

/** True when the Origin names this same server, which can't be a cross-site request. */
export function isSameOrigin(origin: string, host: string | undefined): boolean {
  if (!host) return false;
  try {
    const o = new URL(origin);
    return (o.protocol === 'http:' || o.protocol === 'https:') && o.host.toLowerCase() === host.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * The view token travels in the Authorization header (React Native supports
 * headers on WebSocket) or, for clients that can't set headers, as a
 * subprotocol. Never in the URL, where it would end up in access logs.
 */
function viewToken(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  const m = auth ? /^Bearer\s+(\S+)$/i.exec(auth) : null;
  if (m) return m[1]!;
  const protocols = (req.headers['sec-websocket-protocol'] ?? '').split(',').map((p) => p.trim());
  const p = protocols.find((x) => x.startsWith(PROTOCOL_PREFIX));
  return p ? p.slice(PROTOCOL_PREFIX.length) : null;
}
