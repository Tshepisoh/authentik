import WebSocket from 'ws';
import { z } from 'zod';
import type { AmountCandidate } from '@authentik/shared';

/** The worker is treated as untrusted: its extraction responses are schema-checked and size-capped. */
const extractionSchema = z.object({
  url: z.string().max(4096),
  title: z.string().max(300),
  recipientName: z.string().max(120).nullable(),
  amountMinor: z.number().int().min(0).max(10_000_000_00).nullable(),
  currency: z.string().regex(/^[A-Z]{3}$/).nullable(),
  confidence: z.enum(['high', 'medium', 'low']),
  amountCandidates: z.array(z.object({ amountMinor: z.number().int().min(0), currency: z.string().regex(/^[A-Z]{3}$/), label: z.string().max(60) })).max(10),
  recipientCandidates: z.array(z.string().max(120)).max(10),
  notes: z.array(z.string().max(300)).max(10),
});

export interface WorkerSessionSpec {
  sessionId: string;
  /** The full URL, sent only to the worker over the internal network. */
  url: string;
  viewport: { width: number; height: number };
  ttlSeconds: number;
}

export class WorkerUnavailableError extends Error {
  constructor(readonly reason: string) {
    super(`sandbox worker unavailable: ${reason}`);
  }
}

/** Payment details the worker read from a rendered page (untrusted: the page's own claims). */
export interface WorkerExtraction {
  /** Full URL of the page read. Stays server-side. */
  url: string;
  title: string;
  recipientName: string | null;
  amountMinor: number | null;
  currency: string | null;
  confidence: 'high' | 'medium' | 'low';
  amountCandidates: AmountCandidate[];
  recipientCandidates: string[];
  notes: string[];
}

export interface SandboxWorker {
  readonly configured: boolean;
  createSession(spec: WorkerSessionSpec): Promise<void>;
  closeSession(sessionId: string): Promise<void>;
  openStream(sessionId: string): WebSocket;
  /** Renders `url` in a throwaway isolated browser and reads payment details. */
  extractFromUrl?(url: string): Promise<WorkerExtraction>;
  /** Reads payment details from what a live session is showing; null if the session is gone. */
  extractFromSession?(sessionId: string): Promise<WorkerExtraction | null>;
}

/**
 * Client for the isolated browser worker. The worker lives on a private
 * network; this shared secret is the only credential it ever sees from us,
 * and it grants nothing beyond controlling browser sessions.
 */
export class HttpSandboxWorker implements SandboxWorker {
  constructor(
    private readonly baseUrl: string,
    private readonly secret: string,
  ) {}

  get configured() {
    return Boolean(this.baseUrl && this.secret);
  }

  private headers() {
    return { authorization: `Bearer ${this.secret}`, 'content-type': 'application/json' };
  }

  async createSession(spec: WorkerSessionSpec): Promise<void> {
    if (!this.configured) throw new WorkerUnavailableError('not configured');
    let res: Response;
    try {
      res = await fetch(new URL('/sessions', this.baseUrl), {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(spec),
        signal: AbortSignal.timeout(20_000),
      });
    } catch {
      throw new WorkerUnavailableError('unreachable');
    }
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as { error?: string };
      throw new WorkerUnavailableError(body.error ?? `status ${res.status}`);
    }
  }

  async closeSession(sessionId: string): Promise<void> {
    if (!this.configured) return;
    await fetch(new URL(`/sessions/${encodeURIComponent(sessionId)}`, this.baseUrl), {
      method: 'DELETE',
      headers: this.headers(),
      signal: AbortSignal.timeout(10_000),
    }).catch(() => undefined);
  }

  async extractFromUrl(url: string): Promise<WorkerExtraction> {
    return this.extract('/extract', { url });
  }

  async extractFromSession(sessionId: string): Promise<WorkerExtraction | null> {
    try {
      return await this.extract(`/sessions/${encodeURIComponent(sessionId)}/extract`, {});
    } catch (err) {
      if (err instanceof WorkerUnavailableError && err.reason === 'no_such_session') return null;
      throw err;
    }
  }

  private async extract(path: string, body: object): Promise<WorkerExtraction> {
    if (!this.configured) throw new WorkerUnavailableError('not configured');
    let res: Response;
    try {
      res = await fetch(new URL(path, this.baseUrl), {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(40_000),
      });
    } catch {
      throw new WorkerUnavailableError('unreachable');
    }
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    if (!res.ok) throw new WorkerUnavailableError(data.error ?? `status ${res.status}`);
    const parsed = extractionSchema.safeParse(data);
    if (!parsed.success) throw new WorkerUnavailableError('invalid_response');
    return parsed.data;
  }

  openStream(sessionId: string): WebSocket {
    const url = new URL(`/sessions/${encodeURIComponent(sessionId)}/stream`, this.baseUrl);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    return new WebSocket(url, { headers: { authorization: `Bearer ${this.secret}` }, maxPayload: 4 * 1024 * 1024 });
  }
}
