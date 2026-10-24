import { ipKeyGenerator, rateLimit, type RateLimitRequestHandler } from 'express-rate-limit';
import type { Request } from 'express';

/**
 * Per-user limits for expensive or abusable operations, plus a coarse per-IP
 * limit for everything. Limits are in-memory per instance; put a shared store
 * (e.g. Redis) behind `store` when running more than one API instance.
 */
function keyFor(req: Request): string {
  return req.auth?.uid ? `uid:${req.auth.uid}` : `ip:${ipKeyGenerator(req.ip ?? 'unknown')}`;
}

function limiter(name: string, windowMs: number, limit: number): RateLimitRequestHandler {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    keyGenerator: keyFor,
    handler: (_req, res) => {
      res.status(429).json({
        error: { code: 'rate_limited', message: `Too many ${name} requests. Please wait a moment and try again.` },
      });
    },
  });
}

export const rateLimits = {
  global: () => limiter('', 15 * 60_000, 600),
  scans: () => limiter('scan', 10 * 60_000, 30),
  // Phones check links automatically, so these allow more than manual scans.
  domains: () => limiter('domain check', 10 * 60_000, 120),
  notifications: () => limiter('notification check', 10 * 60_000, 60),
  threats: () => limiter('threat list', 10 * 60_000, 30),
  paymentChecks: () => limiter('payment check', 10 * 60_000, 30),
  sandbox: () => limiter('Sandbox', 10 * 60_000, 6),
  account: () => limiter('account', 15 * 60_000, 10),
};
