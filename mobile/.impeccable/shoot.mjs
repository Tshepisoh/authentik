// Screenshots of the rebuilt screens in the web build, light and dark.
import { createRequire } from 'node:module';
const require = createRequire('C:/Users/TshepisoHlahla/authentik/package.json');
const { chromium } = require('playwright-core');

const out = process.argv[2];
const browser = await chromium.launch();
for (const scheme of ['light', 'dark']) {
  const page = await browser.newPage({ viewport: { width: 400, height: 860 }, colorScheme: scheme, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const shot = (name) => page.screenshot({ path: `${out}/${scheme}-${name}.png`, fullPage: true });
  try {
    await page.goto('http://localhost:8082', { waitUntil: 'networkidle', timeout: 180_000 });
    await page.getByLabel('Email').fill(`${scheme}${Date.now()}@example.com`);
    await page.getByLabel('Password').fill('x');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByText('Stop scams before you trust them').waitFor({ timeout: 20_000 });
    await shot('1-onboarding');
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByText('Straight answers, and your privacy').waitFor();
    await shot('2-onboarding-last');
    await page.getByRole('button', { name: 'Get started' }).click();
    await page.getByText('Manual checks on this device').waitFor({ timeout: 20_000 });
    await shot('3-home-empty');
    await page.getByRole('button', { name: 'Check a link' }).click();
    await page.getByLabel('Website or link').fill('fnb-online-verify.test');
    await page.getByRole('button', { name: 'Check', exact: true }).click();
    await page.getByText('What we checked').waitFor({ timeout: 30_000 });
    await shot('4-website-result');
    await page.goto('http://localhost:8082/', { waitUntil: 'networkidle' });
    await page.getByText('Recent').waitFor();
    await page.waitForTimeout(800);
    await shot('5-home-with-recent');
    console.log(`${scheme}: ok${errors.length ? ` (errors: ${[...new Set(errors)].join(' | ')})` : ''}`);
  } catch (e) {
    await shot('fail');
    console.log(`${scheme}: FAIL ${e.message.split('\n')[0]}${errors.length ? ` (errors: ${[...new Set(errors)].join(' | ')})` : ''}`);
  }
  await page.close();
}
await browser.close();
