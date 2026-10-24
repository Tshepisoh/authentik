import type { Profile } from '@authentik/shared';
import type { Store } from '../../storage/types.js';
import type { Clock } from '../../lib/ids.js';
import type { AuditLog } from '../../security/audit/index.js';
import type { AuthContext, IdentityProvider } from './verifier.js';

export class AccountService {
  constructor(
    private readonly store: Store,
    private readonly identity: IdentityProvider,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
    /** Runs before data deletion, e.g. to end live Sandbox sessions. */
    private readonly beforeDelete: (uid: string) => Promise<void>,
  ) {}

  /** Create-or-retrieve: the first authenticated call after registration creates the profile. */
  async profile(auth: AuthContext): Promise<Profile> {
    const existing = await this.store.profiles.get(auth.uid);
    if (existing) {
      // Keep identity-derived fields in sync without collecting anything new.
      if (existing.email !== auth.email || existing.emailVerified !== auth.emailVerified) {
        await this.store.profiles.update(auth.uid, { email: auth.email, emailVerified: auth.emailVerified });
      }
      return strip({ ...existing, email: auth.email, emailVerified: auth.emailVerified });
    }
    const now = this.clock.now().toISOString();
    const doc = {
      id: auth.uid,
      uid: auth.uid,
      email: auth.email,
      emailVerified: auth.emailVerified,
      onboardingCompletedAt: null,
      createdAt: now,
    };
    await this.store.profiles.put(doc);
    return strip(doc);
  }

  async update(auth: AuthContext, patch: { onboardingCompleted?: boolean }): Promise<Profile> {
    const profile = await this.profile(auth);
    if (patch.onboardingCompleted !== undefined) {
      const onboardingCompletedAt = patch.onboardingCompleted ? (profile.onboardingCompletedAt ?? this.clock.now().toISOString()) : null;
      await this.store.profiles.update(auth.uid, { onboardingCompletedAt });
      return { ...profile, onboardingCompletedAt };
    }
    return profile;
  }

  async revokeSessions(uid: string) {
    await this.identity.revokeSessions(uid);
    this.audit.record({ action: 'account.sessions_revoked', uid });
  }

  /** Deletes everything we hold for the user, then the identity itself. */
  async delete(uid: string) {
    await this.beforeDelete(uid);
    const s = this.store;
    await Promise.all([
      s.reports.deleteByUser(uid),
      s.alerts.deleteByUser(uid),
      s.devices.deleteByUser(uid),
      s.sandboxSessions.deleteByUser(uid),
      s.settings.deleteByUser(uid),
    ]);
    await s.profiles.deleteByUser(uid);
    await this.identity.deleteUser(uid);
    this.audit.record({ action: 'account.deleted', uid });
  }
}

function strip(doc: Profile & { id?: string }): Profile {
  const { uid, email, emailVerified, onboardingCompletedAt, createdAt } = doc;
  return { uid, email, emailVerified, onboardingCompletedAt, createdAt };
}
