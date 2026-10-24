import type { ErrorRequestHandler } from 'express';
import type { Logger } from 'pino';

/** An error whose message is safe to return to the client. */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export const badRequest = (code: string, message: string, details?: unknown) =>
  new HttpError(400, code, message, details);
export const unauthorized = (message = 'Sign in to continue.') => new HttpError(401, 'unauthenticated', message);
export const forbidden = (code = 'forbidden', message = 'You do not have access to this.') =>
  new HttpError(403, code, message);
/** Used for both "missing" and "not yours" so ownership is never revealed. */
export const notFound = (message = 'Not found.') => new HttpError(404, 'not_found', message);
export const conflict = (code: string, message: string) => new HttpError(409, code, message);
export const unavailable = (code: string, message: string) => new HttpError(503, code, message);

/** Final error handler: known errors pass through, everything else becomes a generic 500. */
export function errorHandler(log: Logger): ErrorRequestHandler {
  return (err, req, res, _next) => {
    if (err instanceof HttpError) {
      if (err.status >= 500) log.warn({ code: err.code, path: req.path }, err.message);
      res.status(err.status).json({ error: { code: err.code, message: err.message, details: err.details } });
      return;
    }
    // Body-parser errors (malformed JSON, oversized body).
    if (typeof err === 'object' && err && 'type' in err && typeof err.status === 'number' && err.status < 500) {
      res.status(err.status).json({ error: { code: 'invalid_body', message: 'The request body could not be read.' } });
      return;
    }
    log.error({ err, path: req.path }, 'unhandled error');
    res.status(500).json({ error: { code: 'internal', message: 'Something went wrong. Please try again.' } });
  };
}
