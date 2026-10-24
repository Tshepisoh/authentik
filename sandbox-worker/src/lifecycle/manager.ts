import type WebSocket from 'ws';
import type { Logger } from 'pino';
import type { SandboxClientMessage, SandboxServerMessage } from '@authentik/shared';
import { BrowserSession } from '../browser/session.js';

export interface SessionSpec {
  sessionId: string;
  url: string;
  viewport: { width: number; height: number };
  ttlSeconds: number;
}

/** What the manager needs from a browser session (tests substitute fakes). */
export type SessionBrowser = Pick<BrowserSession, 'start' | 'input' | 'close'> & Partial<Pick<BrowserSession, 'extract' | 'settle'>>;

export type PageExtraction = Awaited<ReturnType<BrowserSession['extract']>>;

export interface ManagerOptions {
  maxSessions: number;
  maxSessionSeconds: number;
  chromiumSandbox: boolean;
  executablePath?: string;
  log: Logger;
  /** Factory override for tests. */
  createSession?: (opts: ConstructorParameters<typeof BrowserSession>[0]) => SessionBrowser;
}

interface Live {
  spec: SessionSpec;
  browser: SessionBrowser;
  stream: WebSocket | null;
  /** Messages produced before the control plane attached (bounded). */
  backlog: SandboxServerMessage[];
  timer: NodeJS.Timeout;
  closing: Promise<void> | null;
}

export class CapacityError extends Error {}
export class IsolationError extends Error {}

/**
 * Owns every browser on this worker: allocation, limits, expiry and cleanup.
 * A session that is not explicitly closed is destroyed at its deadline.
 */
export class SessionManager {
  private readonly live = new Map<string, Live>();
  /** One-shot page reads in progress; they share the session capacity. */
  private oneShots = 0;
  constructor(private readonly opts: ManagerOptions) {}

  get size() {
    return this.live.size;
  }
  get capacity() {
    return this.opts.maxSessions;
  }

  async create(spec: SessionSpec): Promise<void> {
    if (this.live.has(spec.sessionId)) throw new CapacityError('session id already in use');
    if (this.live.size + this.oneShots >= this.opts.maxSessions) throw new CapacityError('worker at capacity');

    const ttl = Math.min(spec.ttlSeconds, this.opts.maxSessionSeconds);
    const factory = this.opts.createSession ?? ((o) => new BrowserSession(o));
    // `entry` is assigned below; the callbacks only run after start() begins.
    // eslint-disable-next-line prefer-const
    let entry: Live;
    const browser = factory({
      sessionId: spec.sessionId,
      url: spec.url,
      viewport: spec.viewport,
      chromiumSandbox: this.opts.chromiumSandbox,
      executablePath: this.opts.executablePath,
      emit: (msg) => this.emit(entry, msg),
      onFatal: (reason) => void this.close(spec.sessionId, reason),
    });
    entry = {
      spec,
      browser,
      stream: null,
      backlog: [],
      timer: setTimeout(() => void this.close(spec.sessionId, 'expired'), ttl * 1000 + 5000),
      closing: null,
    };
    entry.timer.unref();
    this.live.set(spec.sessionId, entry);

    try {
      await browser.start();
    } catch (err) {
      await this.close(spec.sessionId, 'isolation_unavailable');
      this.opts.log.error({ sessionId: spec.sessionId, err: (err as Error).message }, 'session start failed');
      throw new IsolationError((err as Error).message);
    }
    this.opts.log.info({ sessionId: spec.sessionId, ttl }, 'session started');
  }

  /** Attaches the control plane's stream. Only one at a time; a new one replaces the old. */
  attach(sessionId: string, ws: WebSocket): boolean {
    const entry = this.live.get(sessionId);
    if (!entry) return false;
    entry.stream?.close(4409, 'replaced');
    entry.stream = ws;
    for (const m of entry.backlog.splice(0)) ws.send(JSON.stringify(m));
    ws.on('message', (raw) => {
      let msg: SandboxClientMessage;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      void entry.browser.input(msg);
    });
    ws.on('close', () => {
      if (entry.stream === ws) entry.stream = null;
    });
    return true;
  }

  private emit(entry: Live | undefined, msg: SandboxServerMessage) {
    if (!entry) return;
    const ws = entry.stream;
    if (ws && ws.readyState === ws.OPEN) {
      if (msg.type === 'frame' && ws.bufferedAmount > 2_000_000) return; // drop frames under back-pressure
      ws.send(JSON.stringify(msg));
    } else if (msg.type !== 'frame' && entry.backlog.length < 100) {
      entry.backlog.push(msg);
    }
  }

  /** Reads payment details from what a live session is currently showing. */
  async extractFromSession(sessionId: string): Promise<PageExtraction | null> {
    const entry = this.live.get(sessionId);
    if (!entry?.browser.extract) return null;
    return entry.browser.extract();
  }

  /**
   * Opens a URL in a throwaway isolated browser (same isolation as a viewed
   * session: own process, profile and egress proxy), reads payment details, and
   * destroys it. Counts against capacity like any other session.
   */
  async extractFromUrl(url: string): Promise<PageExtraction> {
    if (this.live.size + this.oneShots >= this.opts.maxSessions) throw new CapacityError('worker at capacity');
    this.oneShots++;
    let fatal: string | null = null;
    const factory = this.opts.createSession ?? ((o) => new BrowserSession(o));
    const browser = factory({
      sessionId: `extract-${Date.now()}`,
      url,
      viewport: { width: 390, height: 844 },
      chromiumSandbox: this.opts.chromiumSandbox,
      executablePath: this.opts.executablePath,
      screencast: false,
      emit: () => undefined,
      onFatal: (reason) => {
        fatal = reason;
      },
    });
    const hardStop = setTimeout(() => void browser.close(), 30_000);
    try {
      try {
        await browser.start();
      } catch (err) {
        throw new IsolationError((err as Error).message);
      }
      await browser.settle?.();
      if (fatal) throw new IsolationError(fatal);
      if (!browser.extract) throw new Error('extraction not supported');
      return await browser.extract();
    } finally {
      clearTimeout(hardStop);
      this.oneShots--;
      await browser.close();
    }
  }

  close(sessionId: string, reason: string): Promise<void> {
    const entry = this.live.get(sessionId);
    if (!entry) return Promise.resolve();
    entry.closing ??= (async () => {
      clearTimeout(entry.timer);
      this.live.delete(sessionId);
      try {
        await entry.browser.close();
      } finally {
        if (entry.stream?.readyState === entry.stream?.OPEN) {
          entry.stream?.send(JSON.stringify({ type: 'closed', reason } satisfies SandboxServerMessage));
        }
        entry.stream?.close(1000, reason);
        this.opts.log.info({ sessionId, reason }, 'session destroyed');
      }
    })();
    return entry.closing;
  }

  async closeAll(reason: string) {
    await Promise.all([...this.live.keys()].map((id) => this.close(id, reason)));
  }
}
