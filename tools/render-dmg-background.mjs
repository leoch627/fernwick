// Renders packaging/macos/dmg-background.html to the 1x and 2x PNGs tools/package.py puts
// in the DMG. Run after editing the HTML and commit the PNGs:
//   node tools/render-dmg-background.mjs   (STARRAIL_TEST_CHROMIUM selects Chrome, as for test:ui)
import { chromium } from 'playwright-core';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const source = resolve('packaging/macos/dmg-background.html');
const browser = await chromium.launch({ executablePath: process.env.STARRAIL_TEST_CHROMIUM || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
try {
  for (const [scale, name] of [[1, 'dmg-background.png'], [2, 'dmg-background@2x.png']]) {
    const page = await browser.newPage({ viewport: { width: 660, height: 420 }, deviceScaleFactor: scale });
    await page.goto(pathToFileURL(source).href);
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: resolve('packaging/macos', name), omitBackground: false });
    await page.close();
    console.log(`packaging/macos/${name}`);
  }
} finally {
  await browser.close();
}
