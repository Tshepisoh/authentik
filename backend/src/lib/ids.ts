import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** URL-safe random identifier. 16 bytes ≈ 128 bits. */
export const newId = (bytes = 16) => randomBytes(bytes).toString('base64url');

export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export interface Clock {
  now(): Date;
}
export const systemClock: Clock = { now: () => new Date() };

export const addDays = (d: Date, days: number) => new Date(d.getTime() + days * 86_400_000);
export const addSeconds = (d: Date, s: number) => new Date(d.getTime() + s * 1000);
