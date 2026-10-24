import { describe, expect, it } from 'vitest';
import type { SandboxServerMessage } from '@authentik/shared';
import { BrowserSession } from './session.js';

/**
 * Drives a real Chromium. Opt in with SANDBOX_E2E=1 after `npm run browsers -w @authentik/sandbox-worker`;
 * needs outbound internet access for example.com.
 */
const run = process.env.SANDBOX_E2E === '1' ? describe : describe.skip;

run('BrowserSession (real Chromium)', () => {
  it('reads the amount and recipient from a rendered checkout page', async () => {
    // A checkout that renders its total with JavaScript, as many payment pages do. A data: URL needs no network.
    const html = `<!doctype html><title>Secure checkout</title><body>
      <div><span>Pay to</span> <strong>Takealot Online (RF) (Pty) Ltd</strong></div>
      <div id="t"></div><button id="b"></button>
      <script>setTimeout(()=>{document.getElementById('t').innerHTML='<span>Total due</span> <b>R 1 299,00</b>';document.getElementById('b').textContent='Pay R 1 299,00';},300)</script>`;
    const session = new BrowserSession({
      sessionId: 'e2e-extract-1',
      url: `data:text/html,${encodeURIComponent(html)}`,
      viewport: { width: 390, height: 844 },
      chromiumSandbox: process.platform !== 'linux',
      screencast: false,
      emit: () => undefined,
      onFatal: () => undefined,
    });
    try {
      await session.start();
      await session.settle(3000);
      const r = await session.extract();
      expect(r).toMatchObject({ amountMinor: 129_900, currency: 'ZAR', recipientName: 'Takealot Online (RF) (Pty) Ltd', confidence: 'high' });
    } finally {
      await session.close();
    }
  }, 30_000);

  it('passes the isolation self-test, streams frames and blocks private destinations', async () => {
    const messages: SandboxServerMessage[] = [];
    const fatal: string[] = [];
    const session = new BrowserSession({
      sessionId: 'e2e-session-1',
      url: 'https://example.com/',
      viewport: { width: 390, height: 844 },
      chromiumSandbox: process.platform !== 'linux',
      emit: (m) => messages.push(m),
      onFatal: (r) => fatal.push(r),
    });
    try {
      await session.start();
      const wait = async (pred: () => boolean, ms = 20_000) => {
        const end = Date.now() + ms;
        while (!pred()) {
          if (Date.now() > end) throw new Error('timed out');
          await new Promise((r) => setTimeout(r, 100));
        }
      };
      await wait(() => messages.some((m) => m.type === 'navigated' && m.url.includes('example.com')));
      await wait(() => messages.some((m) => m.type === 'frame'));

      // The page tries to reach cloud metadata and the host's loopback; the proxy must refuse both.
      await session.input({ type: 'navigate', url: 'https://example.com/#probe' });
      const page = (session as unknown as { page: import('playwright-core').Page }).page;
      await page.evaluate(() => {
        void fetch('http://169.254.169.254/latest/meta-data/').catch(() => undefined);
        void fetch('http://127.0.0.1:8080/health').catch(() => undefined);
      });
      await wait(() => messages.filter((m) => m.type === 'event' && m.event.type === 'blocked_destination').length >= 2);
      const blocked = messages.flatMap((m) => (m.type === 'event' && m.event.type === 'blocked_destination' ? [m.event.target] : []));
      expect(blocked).toEqual(expect.arrayContaining(['169.254.169.254', '127.0.0.1']));
      expect(fatal).toEqual([]);
    } finally {
      await session.close();
    }
  }, 60_000);
});
