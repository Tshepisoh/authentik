import type { RequestHandler } from 'express';
import { HttpError, unauthorized } from '../../lib/errors.js';
import type { AuditLog } from '../../security/audit/index.js';
import { InvalidTokenError, type IdentityProvider } from './verifier.js';

/** Rejects any request without a valid, unrevoked identity token. */
export function requireAuth(identity: IdentityProvider, audit: AuditLog): RequestHandler {
  return async (req, _res, next) => {
    const header = req.get('authorization') ?? '';
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    if (!match) throw unauthorized();
    try {
      req.auth = await identity.verify(match[1]!);
    } catch (err) {
      if (err instanceof InvalidTokenError) {
        audit.record({ action: 'auth.rejected', outcome: err.reason });
        throw unauthorized(
          err.reason === 'revoked' ? 'Your session was signed out. Please sign in again.' : 'Sign in to continue.',
        );
      }
      throw err;
    }
    next();
  };
}

/** For destructive account actions: the user must have signed in recently, not just refreshed a token. */
export function requireRecentSignIn(maxAgeSeconds = 300): RequestHandler {
  return (req, _res, next) => {
    const auth = req.auth;
    if (!auth) throw unauthorized();
    if (Date.now() / 1000 - auth.authTime > maxAgeSeconds) {
      throw new HttpError(401, 'reauthentication_required', 'For your security, please sign in again to continue.');
    }
    next();
  };
}

/** Narrowing helper for handlers mounted behind `requireAuth`. */
export function uidOf(req: { auth?: { uid: string } }): string {
  if (!req.auth) throw unauthorized();
  return req.auth.uid;
}
