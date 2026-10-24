import express from 'express';
import helmet from 'helmet';
import type { Deps } from './container.js';
import { errorHandler, notFound } from './lib/errors.js';
import { requireAuth } from './modules/auth/middleware.js';
import { rateLimits } from './security/rate-limiting/index.js';
import { apiRoutes } from './routes.js';

/**
 * The HTTP pipeline, in the order every request passes through it:
 * security headers → body limits → per-IP rate limit → authentication →
 * per-user limits and schema validation (in routes) → handler → minimal response.
 */
export function createApp(deps: Deps) {
  const { config, log } = deps;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.TRUST_PROXY_HOPS);

  app.use(helmet());
  app.use(cors(config.CORS_ORIGINS));
  app.use(express.json({ limit: '32kb' }));
  app.use((req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      // Path only — query strings can carry user data.
      log.info({ method: req.method, path: req.route?.path ?? req.path, status: res.statusCode, ms: Number(process.hrtime.bigint() - start) / 1e6 }, 'request');
    });
    next();
  });
  app.use(rateLimits.global());

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.use('/v1', requireAuth(deps.identity, deps.audit), apiRoutes(deps));

  app.use(() => {
    throw notFound();
  });
  app.use(errorHandler(log));
  return app;
}

function cors(origins: string): express.RequestHandler {
  const allowed = new Set(origins.split(',').map((o) => o.trim()).filter(Boolean));
  return (req, res, next) => {
    const origin = req.get('origin');
    if (origin && allowed.has(origin)) {
      res.set('access-control-allow-origin', origin);
      res.set('vary', 'origin');
      res.set('access-control-allow-headers', 'authorization, content-type');
      res.set('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE');
    }
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  };
}
