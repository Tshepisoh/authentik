import type { Collection, Doc, ListOptions, Store } from './types.js';
import { systemClock, type Clock } from '../lib/ids.js';

/** In-process store for local development and tests. Not for production (config refuses it). */
export class MemoryCollection<T extends Doc> implements Collection<T> {
  private readonly docs = new Map<string, T>();
  constructor(private readonly clock: Clock = systemClock) {}

  private live(doc: T | undefined): T | null {
    if (!doc) return null;
    if (doc.expiresAt && new Date(doc.expiresAt) <= this.clock.now()) {
      this.docs.delete(doc.id);
      return null;
    }
    return structuredClone(doc);
  }

  async get(id: string) {
    return this.live(this.docs.get(id));
  }
  async put(doc: T) {
    this.docs.set(doc.id, structuredClone(doc));
  }
  async update(id: string, patch: Partial<Omit<T, 'id' | 'uid'>>) {
    const existing = this.docs.get(id);
    if (existing) this.docs.set(id, { ...existing, ...structuredClone(patch) });
  }
  async delete(id: string) {
    this.docs.delete(id);
  }
  async listByUser(uid: string, options: ListOptions<T> = {}) {
    const out: T[] = [];
    for (const doc of [...this.docs.values()]) {
      if (doc.uid !== uid) continue;
      if (options.where && doc[options.where.field] !== options.where.equals) continue;
      const live = this.live(doc);
      if (live) out.push(live);
    }
    out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return out.slice(0, options.limit ?? 50);
  }
  async deleteByUser(uid: string) {
    let n = 0;
    for (const [id, doc] of [...this.docs]) {
      if (doc.uid === uid) {
        this.docs.delete(id);
        n++;
      }
    }
    return n;
  }
  async purgeExpired(now: Date) {
    let n = 0;
    for (const [id, doc] of [...this.docs]) {
      if (doc.expiresAt && new Date(doc.expiresAt) <= now) {
        this.docs.delete(id);
        n++;
      }
    }
    return n;
  }
}

export function createMemoryStore(clock: Clock = systemClock): Store {
  return {
    profiles: new MemoryCollection(clock),
    settings: new MemoryCollection(clock),
    devices: new MemoryCollection(clock),
    reports: new MemoryCollection(clock),
    alerts: new MemoryCollection(clock),
    sandboxSessions: new MemoryCollection(clock),
  };
}
