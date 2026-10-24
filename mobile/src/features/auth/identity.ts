import AsyncStorage from '@react-native-async-storage/async-storage';
import { getApps, initializeApp } from 'firebase/app';
import {
  createUserWithEmailAndPassword,
  EmailAuthProvider,
  getReactNativePersistence,
  initializeAuth,
  onIdTokenChanged,
  reauthenticateWithCredential,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut as fbSignOut,
  type Auth,
} from '@firebase/auth';
import { config } from '@/shared/config';

// '@firebase/auth' (not 'firebase/auth'): only it has a react-native export condition, which carries getReactNativePersistence.

export interface SessionUser {
  uid: string;
  email: string | null;
  emailVerified: boolean;
}

/** What the app needs from an identity provider. Passwords go straight to the provider, never to the Authentik API. */
export interface Identity {
  subscribe(cb: (user: SessionUser | null) => void): () => void;
  getToken(forceRefresh?: boolean): Promise<string | null>;
  signIn(email: string, password: string): Promise<void>;
  register(email: string, password: string): Promise<void>;
  sendPasswordReset(email: string): Promise<void>;
  resendVerification(): Promise<void>;
  reauthenticate(password: string): Promise<void>;
  reload(): Promise<void>;
  signOut(): Promise<void>;
}

class FirebaseIdentity implements Identity {
  private readonly auth: Auth;
  constructor() {
    const app = getApps()[0] ?? initializeApp(config.firebase);
    this.auth = initializeAuth(app, { persistence: getReactNativePersistence(AsyncStorage) });
  }
  subscribe(cb: (u: SessionUser | null) => void) {
    return onIdTokenChanged(this.auth, (u) => cb(u ? { uid: u.uid, email: u.email, emailVerified: u.emailVerified } : null));
  }
  async getToken(force = false) {
    return (await this.auth.currentUser?.getIdToken(force)) ?? null;
  }
  async signIn(email: string, password: string) {
    await signInWithEmailAndPassword(this.auth, email.trim(), password);
  }
  async register(email: string, password: string) {
    const { user } = await createUserWithEmailAndPassword(this.auth, email.trim(), password);
    await sendEmailVerification(user).catch(() => undefined);
  }
  async sendPasswordReset(email: string) {
    await sendPasswordResetEmail(this.auth, email.trim());
  }
  async resendVerification() {
    if (this.auth.currentUser) await sendEmailVerification(this.auth.currentUser);
  }
  async reauthenticate(password: string) {
    const u = this.auth.currentUser;
    if (!u?.email) throw new Error('Not signed in');
    await reauthenticateWithCredential(u, EmailAuthProvider.credential(u.email, password));
    await u.getIdToken(true);
  }
  async reload() {
    await this.auth.currentUser?.reload();
    await this.auth.currentUser?.getIdToken(true);
  }
  async signOut() {
    await fbSignOut(this.auth);
  }
}

// A made-up dev user id, not a secret, so AsyncStorage (which also works on web) is fine.
const DEV_KEY = 'authentik.dev.uid';

/** Local development only: works against a backend with AUTH_MODE=dev, which production refuses. */
class DevIdentity implements Identity {
  private listeners = new Set<(u: SessionUser | null) => void>();
  private user: SessionUser | null = null;
  private ready = AsyncStorage.getItem(DEV_KEY).then((uid) => {
    this.user = uid ? { uid, email: `${uid}@dev.authentik.test`, emailVerified: true } : null;
  });

  subscribe(cb: (u: SessionUser | null) => void) {
    this.listeners.add(cb);
    void this.ready.then(() => cb(this.user));
    return () => void this.listeners.delete(cb);
  }
  private set(u: SessionUser | null) {
    this.user = u;
    this.listeners.forEach((l) => l(u));
  }
  async getToken() {
    await this.ready;
    return this.user ? `dev:${this.user.uid}` : null;
  }
  async signIn(email: string) {
    const uid = email.trim().toLowerCase().replace(/@.*/, '').replace(/[^a-z0-9_-]/g, '').slice(0, 32) || 'dev';
    await AsyncStorage.setItem(DEV_KEY, uid);
    this.set({ uid, email: email.trim(), emailVerified: true });
  }
  async register(email: string) {
    await this.signIn(email);
  }
  async sendPasswordReset() {}
  async resendVerification() {}
  async reauthenticate() {}
  async reload() {}
  async signOut() {
    await AsyncStorage.removeItem(DEV_KEY);
    this.set(null);
  }
}

export const identity: Identity = config.authMode === 'dev' ? new DevIdentity() : new FirebaseIdentity();

/** Maps provider error codes to messages that don't reveal whether an account exists. */
export function authErrorMessage(err: unknown): string {
  const code = (err as { code?: string })?.code ?? '';
  if (['auth/invalid-credential', 'auth/wrong-password', 'auth/user-not-found', 'auth/invalid-email'].includes(code)) {
    return 'That email and password combination did not work.';
  }
  if (code === 'auth/email-already-in-use') return 'Could not create an account with that email. Try signing in instead.';
  if (code === 'auth/weak-password') return 'Choose a stronger password (at least 8 characters, mixing letters and numbers).';
  if (code === 'auth/too-many-requests') return 'Too many attempts. Please wait a few minutes and try again.';
  if (code === 'auth/network-request-failed') return 'No connection. Check your internet and try again.';
  return 'Something went wrong. Please try again.';
}
