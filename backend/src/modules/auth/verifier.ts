import type { Auth } from 'firebase-admin/auth';

export interface AuthContext {
  uid: string;
  email: string | null;
  emailVerified: boolean;
  /** Seconds since epoch of the user's last real sign-in (not token refresh). */
  authTime: number;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

export class InvalidTokenError extends Error {
  constructor(readonly reason: 'invalid' | 'revoked' | 'expired' | 'disabled') {
    super(`token ${reason}`);
  }
}

/** Identity provider operations the API needs. Firebase in deployments; a fake in dev/tests. */
export interface IdentityProvider {
  verify(token: string): Promise<AuthContext>;
  revokeSessions(uid: string): Promise<void>;
  deleteUser(uid: string): Promise<void>;
}

export class FirebaseIdentityProvider implements IdentityProvider {
  constructor(private readonly auth: Auth) {}

  async verify(token: string): Promise<AuthContext> {
    try {
      // checkRevoked=true: tokens issued before "sign out everywhere" stop working immediately.
      const decoded = await this.auth.verifyIdToken(token, true);
      return {
        uid: decoded.uid,
        email: decoded.email ?? null,
        emailVerified: decoded.email_verified ?? false,
        authTime: decoded.auth_time,
      };
    } catch (err) {
      const code = (err as { code?: string }).code ?? '';
      if (code === 'auth/id-token-revoked') throw new InvalidTokenError('revoked');
      if (code === 'auth/id-token-expired') throw new InvalidTokenError('expired');
      if (code === 'auth/user-disabled') throw new InvalidTokenError('disabled');
      throw new InvalidTokenError('invalid');
    }
  }

  async revokeSessions(uid: string) {
    await this.auth.revokeRefreshTokens(uid);
  }

  async deleteUser(uid: string) {
    try {
      await this.auth.deleteUser(uid);
    } catch (err) {
      if ((err as { code?: string }).code !== 'auth/user-not-found') throw err;
    }
  }
}

/**
 * Local-development identity: `Bearer dev:<uid>` (append `:unverified` to
 * simulate an unverified email). Config refuses this mode in production.
 */
export class DevIdentityProvider implements IdentityProvider {
  private readonly revokedAt = new Map<string, number>();

  async verify(token: string): Promise<AuthContext> {
    const match = /^dev:([A-Za-z0-9_-]{1,64})(:unverified)?$/.exec(token);
    if (!match) throw new InvalidTokenError('invalid');
    const uid = match[1]!;
    if (this.revokedAt.has(uid)) throw new InvalidTokenError('revoked');
    return {
      uid,
      email: `${uid}@dev.authentik.test`,
      emailVerified: !match[2],
      authTime: Math.floor(Date.now() / 1000),
    };
  }
  async revokeSessions(uid: string) {
    this.revokedAt.set(uid, Date.now());
  }
  async deleteUser(uid: string) {
    this.revokedAt.set(uid, Date.now());
  }
}
