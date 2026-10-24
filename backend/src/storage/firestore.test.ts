import { describe, expect, it } from 'vitest';
import { Timestamp } from 'firebase-admin/firestore';
import { stripUndefined } from './firestore.js';

describe('stripUndefined', () => {
  it('removes undefined at any depth, including inside arrays', () => {
    const ts = Timestamp.fromMillis(0);
    expect(
      stripUndefined({ a: 1, b: undefined, c: { d: undefined, e: null }, f: [{ g: undefined, h: 2 }], ts }),
    ).toEqual({ a: 1, c: { e: null }, f: [{ h: 2 }], ts });
  });

  it('leaves non-plain objects such as Timestamps untouched', () => {
    const ts = Timestamp.fromMillis(1234);
    expect((stripUndefined({ ts }) as { ts: unknown }).ts).toBe(ts);
  });
});
