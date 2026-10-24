// Renders the A-check monogram (logo option 2) into the app's icon PNGs.
// Usage: node render-icons.mjs <mobile/assets dir>
import { createRequire } from 'node:module';
const require = createRequire('C:/Users/TshepisoHlahla/authentik/package.json');
const { chromium } = require('playwright-core');

const out = process.argv[2];
const BLUE = '#3451C7';

// viewBox 0 0 64 64; nudged left so the mark's visual centre sits on the canvas centre.
const mark = (color, width = 7) => `
  <g transform="translate(-1.5 0)" fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round">
    <path d="M13 55 L32 9 L51 55"/><path d="M20 38 L27 47 L54 20"/>
  </g>`;

/** size: PNG px; markPx: rendered size of the 64-unit viewBox; bg: fill or null; radius: corner px. */
const icons = [
  { file: 'icon.png', size: 1024, markPx: 640, bg: BLUE, radius: 0 },
  { file: 'android-icon-foreground.png', size: 1024, markPx: 500, bg: null },
  { file: 'android-icon-background.png', size: 1024, markPx: 0, bg: BLUE, radius: 0 },
  { file: 'android-icon-monochrome.png', size: 1024, markPx: 500, bg: null },
  { file: 'splash-icon.png', size: 1024, markPx: 600, bg: BLUE, radius: 232 },
  { file: 'favicon.png', size: 48, markPx: 32, bg: BLUE, radius: 12, width: 8 },
  { file: 'notification-icon.png', size: 96, markPx: 88, bg: null, width: 8 },
  // White on transparent; the app tints it (Image tintColor) per theme.
  { file: 'brand-mark.png', size: 216, markPx: 216, bg: null, width: 6.5 },
];

const browser = await chromium.launch();
const page = await browser.newPage({ deviceScaleFactor: 1 });
for (const i of icons) {
  const off = (i.size - i.markPx) / 2;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${i.size}" height="${i.size}" viewBox="0 0 ${i.size} ${i.size}">
    ${i.bg ? `<rect width="${i.size}" height="${i.size}" rx="${i.radius ?? 0}" fill="${i.bg}"/>` : ''}
    ${i.markPx ? `<svg x="${off}" y="${off}" width="${i.markPx}" height="${i.markPx}" viewBox="0 0 64 64">${mark('#FFFFFF', i.width)}</svg>` : ''}
  </svg>`;
  await page.setViewportSize({ width: i.size, height: i.size });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg}</body></html>`);
  await page.locator('svg').first().screenshot({ path: `${out}/${i.file}`, omitBackground: true });
  console.log('wrote', i.file);
}

// Wordmark: "Authentik" in Schibsted Grotesk Bold, white on transparent, at 3x of 30px.
await page.setViewportSize({ width: 800, height: 200 });
await page.setContent(`<html><head>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@700&display=block">
  </head><body style="margin:0;background:transparent">
  <span id="w" style="display:inline-block;font-family:'Schibsted Grotesk';font-weight:700;font-size:90px;line-height:108px;letter-spacing:-0.9px;color:#FFFFFF;padding:0 3px">Authentik</span>
  </body></html>`);
await page.evaluate(() => document.fonts.ready);
await page.locator('#w').screenshot({ path: `${out}/wordmark.png`, omitBackground: true });
console.log('wrote wordmark.png');
await browser.close();
