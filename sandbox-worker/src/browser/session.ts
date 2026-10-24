import { chromium, type Browser, type BrowserContext, type CDPSession, type Page } from 'playwright-core';
import {
  checkStaticDestination,
  normalizeTargetUrl,
  registrableDomain,
  SANDBOX_ALLOWED_KEYS,
  type SandboxClientMessage,
  type SandboxEvent,
  type SandboxServerMessage,
} from '@authentik/shared';
import { ISOLATION_PROBE_HOST, startEgressProxy, type EgressProxy } from '../network-policy/egress-proxy.js';
import { COLLECT_PAYMENT_EVIDENCE, interpretPaymentEvidence, type InterpretedPayment, type RawPaymentEvidence } from './extract.js';

export interface BrowserSessionOptions {
  sessionId: string;
  url: string;
  viewport: { width: number; height: number };
  chromiumSandbox: boolean;
  /** Off for one-shot page reads, which nobody watches. Default on. */
  screencast?: boolean;
  executablePath?: string;
  emit: (msg: SandboxServerMessage) => void;
  /** The session must be destroyed (crash, isolation failure). */
  onFatal: (reason: string) => void;
}

/** Max ~12 frames/s to the viewer: smooth enough for browsing, ~75% less than an animated page produces. */
const FRAME_INTERVAL_MS = 80;

const MOBILE_UA =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';

/** Init script: report (not grant) permission requests. Enforcement is the empty permission set on the context. */
const PERMISSION_PROBE = `(() => {
  const report = (kind) => { try { window.__authentikPermission(kind); } catch {} };
  const wrap = (obj, name, kind) => {
    if (!obj || typeof obj[name] !== 'function') return;
    const orig = obj[name].bind(obj);
    obj[name] = (...args) => { report(kind); return orig(...args); };
  };
  wrap(navigator.geolocation, 'getCurrentPosition', 'location');
  wrap(navigator.geolocation, 'watchPosition', 'location');
  wrap(navigator.mediaDevices, 'getUserMedia', 'camera/microphone');
  wrap(navigator.mediaDevices, 'getDisplayMedia', 'screen');
  if (window.Notification) wrap(window.Notification, 'requestPermission', 'notifications');
  wrap(navigator.clipboard, 'readText', 'clipboard');
  wrap(navigator, 'requestMIDIAccess', 'midi');
  wrap(navigator.usb, 'requestDevice', 'usb');
  wrap(navigator.bluetooth, 'requestDevice', 'bluetooth');
})();`;

/**
 * One disposable browser for one session. Every session gets its own
 * Chromium process, its own throwaway profile (deleted when the browser
 * closes) and its own egress proxy. Nothing — cookies, storage, cache — is
 * shared between sessions or imported from the user's device.
 */
export class BrowserSession {
  private proxy: EgressProxy | null = null;
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private page: Page | null = null;
  private cdp: CDPSession | null = null;
  private currentDomain: string | null = null;
  private lastInputAt = 0;
  private closed = false;
  readonly events: SandboxEvent[] = [];

  constructor(private readonly opts: BrowserSessionOptions) {}

  private event(e: Omit<SandboxEvent, 'at'>) {
    const full = { ...e, at: new Date().toISOString() };
    if (this.events.length < 500) this.events.push(full);
    this.opts.emit({ type: 'event', event: full });
  }

  /** Throws if isolation can't be established; the caller must then refuse the session. */
  async start(): Promise<void> {
    this.proxy = await startEgressProxy({
      onBlocked: (host, code) =>
        this.event({ type: 'blocked_destination', target: host, detail: code.replace(/_/g, ' '), severity: 'critical' }),
      onFailure: (reason) => {
        this.event({ type: 'isolation_failure', detail: reason, severity: 'critical' });
        this.opts.onFatal('isolation_failure');
      },
    });

    this.browser = await chromium.launch({
      headless: true,
      chromiumSandbox: this.opts.chromiumSandbox,
      executablePath: this.opts.executablePath,
      timeout: 15_000,
      args: [
        `--proxy-server=http://127.0.0.1:${this.proxy.port}`,
        // Chromium bypasses proxies for loopback by default; "<-loopback>" removes that exception.
        '--proxy-bypass-list=<-loopback>',
        '--disable-quic',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--disable-background-networking',
        '--disable-component-update',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-sync',
        '--disable-breakpad',
        '--no-first-run',
        '--no-pings',
        '--mute-audio',
        '--renderer-process-limit=2',
        '--js-flags=--max-old-space-size=256',
        '--disable-features=InterestFeedContentSuggestions,Translate,OptimizationHints,MediaRouter',
      ],
    });

    this.context = await this.browser.newContext({
      viewport: this.opts.viewport,
      deviceScaleFactor: 1,
      isMobile: true,
      hasTouch: true,
      userAgent: MOBILE_UA,
      locale: 'en-ZA',
      timezoneId: 'Africa/Johannesburg',
      acceptDownloads: false,
      permissions: [],
      serviceWorkers: 'block',
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
    });
    await this.context.exposeBinding('__authentikPermission', (_src, kind: unknown) => {
      this.event({ type: 'permission_denied', detail: String(kind).slice(0, 40), severity: 'warning' });
    });
    await this.context.addInitScript(PERMISSION_PROBE);

    this.page = await this.context.newPage();
    await this.verifyIsolation(this.page);

    this.context.on('page', (p) => {
      if (p === this.page) return;
      this.event({ type: 'popup_blocked', target: safeHost(p.url()), severity: 'warning' });
      void p.close().catch(() => undefined);
    });
    this.wirePage(this.page);
    if (this.opts.screencast !== false) await this.startScreencast(this.page);

    void this.page
      .goto(this.opts.url, { waitUntil: 'commit', timeout: 20_000 })
      .catch(() => this.event({ type: 'navigation', target: safeHost(this.opts.url), detail: 'the site did not respond', severity: 'info' }));
  }

  /**
   * Proves the browser's traffic actually goes through our proxy before any
   * untrusted content loads: request a reserved hostname and require the proxy
   * to have seen it. If it didn't, the browser has a route we don't control.
   */
  private async verifyIsolation(page: Page) {
    await page.goto(`http://${ISOLATION_PROBE_HOST}/`, { timeout: 5000 }).catch(() => undefined);
    if (!this.proxy?.seen.has(ISOLATION_PROBE_HOST)) {
      throw new Error('isolation self-test failed: browser traffic did not reach the egress proxy');
    }
    await page.goto('about:blank').catch(() => undefined);
  }

  private wirePage(page: Page) {
    page.on('download', (d) => {
      this.event({ type: 'download_blocked', target: safeHost(d.url()), detail: d.suggestedFilename().slice(0, 80), severity: 'warning' });
      void d.cancel().catch(() => undefined);
    });
    page.on('dialog', (d) => {
      this.event({ type: 'dialog_dismissed', detail: d.type(), severity: 'info' });
      void d.dismiss().catch(() => undefined);
    });
    page.on('filechooser', () => {
      this.event({ type: 'file_chooser_blocked', severity: 'warning' });
    });
    page.on('crash', () => {
      this.event({ type: 'browser_crashed', severity: 'critical' });
      this.opts.onFatal('browser_crashed');
    });
    page.on('framenavigated', (frame) => {
      if (frame !== page.mainFrame()) return;
      const url = frame.url();
      if (!/^https?:/.test(url)) return;
      const host = safeHost(url);
      const domain = registrableDomain(host);
      if (this.currentDomain && domain !== this.currentDomain) {
        const userInitiated = Date.now() - this.lastInputAt < 2000;
        this.event({
          type: userInitiated ? 'navigation' : 'cross_domain_redirect',
          target: host,
          detail: userInitiated ? undefined : `moved from ${this.currentDomain} without user action`,
          severity: userInitiated ? 'info' : 'warning',
        });
      }
      this.currentDomain = domain;
      void page.title().then(
        (title) => this.opts.emit({ type: 'navigated', url, title: title.slice(0, 300) }),
        () => this.opts.emit({ type: 'navigated', url, title: '' }),
      );
    });
  }

  private async startScreencast(page: Page) {
    this.cdp = await page.context().newCDPSession(page);
    // Animated pages produce ~50 frames/s; phones can't decode that over Wi-Fi without stutter.
    // Send at most one frame per interval, and always the latest one once things settle (trailing edge).
    let latest: SandboxServerMessage | null = null;
    let lastSent = 0;
    let timer: NodeJS.Timeout | null = null;
    const flush = () => {
      timer = null;
      if (!latest || this.closed) return;
      this.opts.emit(latest);
      latest = null;
      lastSent = Date.now();
    };
    this.cdp.on('Page.screencastFrame', ({ data, sessionId, metadata }) => {
      // Always ack, or Chromium stops producing frames.
      void this.cdp?.send('Page.screencastFrameAck', { sessionId }).catch(() => undefined);
      latest = {
        type: 'frame',
        data,
        width: Math.round(metadata.deviceWidth ?? this.opts.viewport.width),
        height: Math.round(metadata.deviceHeight ?? this.opts.viewport.height),
      };
      const wait = FRAME_INTERVAL_MS - (Date.now() - lastSent);
      if (wait <= 0) flush();
      else timer ??= setTimeout(flush, wait);
    });
    await this.cdp.send('Page.startScreencast', {
      format: 'jpeg',
      quality: 55,
      maxWidth: this.opts.viewport.width,
      maxHeight: this.opts.viewport.height,
      everyNthFrame: 1,
    });
  }

  /** Applies one validated viewer input. Errors are swallowed: a failed tap must not kill the session. */
  async input(msg: SandboxClientMessage): Promise<void> {
    const page = this.page;
    if (!page || this.closed) return;
    this.lastInputAt = Date.now();
    const { width, height } = this.opts.viewport;
    try {
      switch (msg.type) {
        case 'tap':
          await page.touchscreen.tap(clamp(Number(msg.x), width), clamp(Number(msg.y), height));
          break;
        case 'scroll':
          await page.mouse.move(width / 2, height / 2);
          await page.mouse.wheel(msg.dx, msg.dy);
          break;
        case 'type':
          if (typeof msg.text === 'string') await page.keyboard.insertText(msg.text.slice(0, 500));
          break;
        case 'key':
          // Only plain navigation keys: no shortcuts such as Control+S or DevTools chords.
          if ((SANDBOX_ALLOWED_KEYS as readonly string[]).includes(msg.key)) await page.keyboard.press(msg.key);
          break;
        case 'back':
          await page.goBack({ timeout: 10_000 });
          break;
        case 'forward':
          await page.goForward({ timeout: 10_000 });
          break;
        case 'reload':
          await page.reload({ timeout: 15_000 });
          break;
        case 'navigate': {
          // The control plane validated this already; check again — the proxy is the final word.
          const n = normalizeTargetUrl(msg.url);
          if (!n.ok || !checkStaticDestination(n.url).allowed) {
            this.event({ type: 'blocked_destination', target: n.ok ? n.url.hostname : undefined, detail: 'address not permitted', severity: 'warning' });
            return;
          }
          await page.goto(n.url.href, { waitUntil: 'commit', timeout: 20_000 });
          break;
        }
      }
    } catch {
      /* navigation timeouts and detached frames are expected on hostile pages */
    }
  }

  /** Waits (bounded) for the page and its scripts to finish loading, for pages that render totals late. */
  async settle(timeoutMs = 12_000): Promise<void> {
    const page = this.page;
    if (!page) return;
    const deadline = Date.now() + timeoutMs;
    await page.waitForLoadState('load', { timeout: timeoutMs }).catch(() => undefined);
    await page.waitForLoadState('networkidle', { timeout: Math.max(0, deadline - Date.now()) }).catch(() => undefined);
    await page.waitForTimeout(Math.min(1500, Math.max(0, deadline - Date.now()))).catch(() => undefined);
  }

  /** Reads payment details from the page currently shown. The full URL stays inside the platform. */
  async extract(): Promise<{ url: string; title: string } & InterpretedPayment> {
    const page = this.page;
    if (!page || this.closed) throw new Error('session not active');
    const raw = await Promise.race([
      page.evaluate(COLLECT_PAYMENT_EVIDENCE) as Promise<RawPaymentEvidence>,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('page did not respond')), 8000)),
    ]);
    return { url: page.url(), title: raw.title, ...interpretPaymentEvidence(raw) };
  }

  /** Destroys the browser, its profile and the proxy. Safe to call more than once. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.cdp?.send('Page.stopScreencast').catch(() => undefined);
    await withTimeout(this.context?.close(), 5000);
    // Closing the browser kills the Chromium process tree and deletes its temporary profile directory.
    await withTimeout(this.browser?.close(), 10_000);
    await this.proxy?.close().catch(() => undefined);
    this.page = null;
    this.context = null;
    this.browser = null;
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

const clamp = (v: number, max: number) => Math.max(0, Math.min(max - 1, v));

async function withTimeout(p: Promise<unknown> | undefined, ms: number) {
  if (!p) return;
  await Promise.race([p.catch(() => undefined), new Promise((r) => setTimeout(r, ms))]);
}
