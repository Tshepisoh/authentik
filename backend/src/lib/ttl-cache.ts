import type { Clock } from './ids.js';

/** A small in-memory cache with per-entry expiry and a size cap (oldest entries go first). */
export class TtlCache<V> {
  private readonly entries = new Map<string, { value: V; expiresAt: number }>();

  constructor(
    private readonly clock: Clock,
    private readonly maxEntries = 5000,
  ) {}

  get(key: string): V | undefined {
    const hit = this.entries.get(key);
    if (!hit) return undefined;
    if (hit.expiresAt <= this.clock.now().getTime()) {
      this.entries.delete(key);
      return undefined;
    }
    return hit.value;
  }

  set(key: string, value: V, ttlSeconds: number): void {
    if (ttlSeconds <= 0) return;
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAt: this.clock.now().getTime() + ttlSeconds * 1000 });
    while (this.entries.size > this.maxEntries) {
      this.entries.delete(this.entries.keys().next().value!);
    }
  }

  get size() {
    return this.entries.size;
  }
}
