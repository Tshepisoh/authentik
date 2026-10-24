import { Timestamp, type DocumentData, type Firestore, type Query } from 'firebase-admin/firestore';
import type { Collection, Doc, ListOptions, Store } from './types.js';

/**
 * Firestore-backed collections. Clients never talk to Firestore directly —
 * firestore.rules denies all client access — so every read and write goes
 * through the API's authorization checks.
 *
 * Expiry: documents with `expiresAt` also get a `_ttl` Timestamp. Expired
 * documents are filtered out on read and physically deleted by
 * `purgeExpired`, which the retention sweeper runs on a schedule. (Firestore's
 * own TTL policies need billing enabled; `_ttl` is already in place if you
 * turn them on later.)
 */
class FirestoreCollection<T extends Doc> implements Collection<T> {
  constructor(
    private readonly db: Firestore,
    private readonly name: string,
  ) {}

  private ref(id: string) {
    return this.db.collection(this.name).doc(id);
  }

  private toStored(doc: Partial<T>): Record<string, unknown> {
    const stored = stripUndefined({ ...doc }) as Record<string, unknown>;
    if (doc.expiresAt) stored._ttl = Timestamp.fromDate(new Date(doc.expiresAt));
    return stored;
  }

  private fromStored(data: DocumentData | undefined): T | null {
    if (!data) return null;
    const { _ttl: _ignored, ...doc } = data;
    if (typeof doc.expiresAt === 'string' && new Date(doc.expiresAt) <= new Date()) return null;
    return doc as T;
  }

  async get(id: string) {
    const snap = await this.ref(id).get();
    return this.fromStored(snap.data());
  }
  async put(doc: T) {
    await this.ref(doc.id).set(this.toStored(doc));
  }
  async update(id: string, patch: Partial<Omit<T, 'id' | 'uid'>>) {
    await this.ref(id).set(this.toStored(patch as Partial<T>), { merge: true });
  }
  async delete(id: string) {
    await this.ref(id).delete();
  }
  async listByUser(uid: string, options: ListOptions<T> = {}) {
    let q: Query = this.db.collection(this.name).where('uid', '==', uid);
    if (options.where) q = q.where(options.where.field, '==', options.where.equals);
    const snap = await q.orderBy('createdAt', 'desc').limit(options.limit ?? 50).get();
    return snap.docs.map((d) => this.fromStored(d.data())).filter((d): d is T => d !== null);
  }
  async deleteByUser(uid: string) {
    let total = 0;
    // Batched writes are capped at 500 operations.
    for (;;) {
      const snap = await this.db.collection(this.name).where('uid', '==', uid).limit(400).get();
      if (snap.empty) return total;
      const batch = this.db.batch();
      snap.docs.forEach((d) => batch.delete(d.ref));
      await batch.commit();
      total += snap.size;
    }
  }
  async purgeExpired(now: Date) {
    let total = 0;
    // Single-field range query: served by Firestore's automatic index on `_ttl`.
    for (;;) {
      const snap = await this.db.collection(this.name).where('_ttl', '<=', Timestamp.fromDate(now)).limit(400).get();
      if (snap.empty) return total;
      const batch = this.db.batch();
      snap.docs.forEach((d) => batch.delete(d.ref));
      await batch.commit();
      total += snap.size;
    }
  }
}

/**
 * Firestore rejects `undefined` anywhere in a document, while our types use
 * optional fields freely (e.g. `CheckRun.detail`). Drop them before writing.
 * Only plain objects and arrays are walked; Timestamps and other values pass through.
 */
export function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripUndefined);
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(
      Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, stripUndefined(v)]),
    );
  }
  return value;
}

export function createFirestoreStore(db: Firestore): Store {
  return {
    profiles: new FirestoreCollection(db, 'profiles'),
    settings: new FirestoreCollection(db, 'settings'),
    devices: new FirestoreCollection(db, 'devices'),
    reports: new FirestoreCollection(db, 'reports'),
    alerts: new FirestoreCollection(db, 'alerts'),
    sandboxSessions: new FirestoreCollection(db, 'sandboxSessions'),
  };
}
