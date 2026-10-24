import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { Profile } from '@authentik/shared';
import { api } from '@/shared/api/client';
import { identity, type SessionUser } from './identity';

interface AuthState {
  /** True until we know whether someone is signed in. */
  initializing: boolean;
  user: SessionUser | null;
  profile: Profile | null;
  profileError: string | null;
  refreshProfile: () => Promise<void>;
  completeOnboarding: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [initializing, setInitializing] = useState(true);
  const [user, setUser] = useState<SessionUser | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);

  const refreshProfile = useCallback(async () => {
    try {
      // Create-or-retrieve: the first call after registration creates the Authentik profile.
      setProfile(await api.me());
      setProfileError(null);
    } catch (e) {
      setProfileError((e as Error).message);
    }
  }, []);

  useEffect(
    () =>
      identity.subscribe(async (u) => {
        setUser(u);
        if (u) await refreshProfile();
        else setProfile(null);
        setInitializing(false);
      }),
    [refreshProfile],
  );

  const value = useMemo<AuthState>(
    () => ({
      initializing,
      user,
      profile,
      profileError,
      refreshProfile,
      completeOnboarding: async () => setProfile(await api.completeOnboarding()),
      signOut: async () => {
        await identity.signOut();
        setProfile(null);
      },
    }),
    [initializing, user, profile, profileError, refreshProfile],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
