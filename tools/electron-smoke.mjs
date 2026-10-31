import { _electron as electron } from 'playwright-core';
import { mkdir } from 'node:fs/promises';
import assert from 'node:assert/strict';
await mkdir('work/electron-profile', { recursive: true });
const application = await electron.launch({ args: ['.', '--demo', '--no-sandbox', '--ozone-platform=headless'], env: { ...process.env, TZ: 'Asia/Tokyo', XDG_CONFIG_HOME: `${process.cwd()}/work/electron-profile`, XDG_CACHE_HOME: `${process.cwd()}/work/electron-cache` } });
try {
  const page = await application.firstWindow();
  await page.getByText('pr***@example.invalid', { exact: true }).first().waitFor({ timeout: 15000 });
  await page.getByRole('button', { name: '连接网络', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: '网络组件尚未安装' }).waitFor();
  assert.equal(await page.evaluate(() => typeof window.require), 'undefined');
  assert.equal(await page.evaluate(() => typeof window.process), 'undefined');
  const result = await page.evaluate(() => window.starrail.command({ type: 'state' }));
  assert.equal(result.state.loggedIn, true); assert.equal(result.state.connection, 'Disconnected');
  const encoded = JSON.stringify(result.state); assert.equal(encoded.includes('development-fixture-only'), false); assert.equal(encoded.includes('00000000-0000-4000-8000-'), false);
  await page.screenshot({ path: 'work/electron-desktop.png' });
  console.log('Electron integration passed: isolated renderer/preload, native IPC, worker parsing, demo sync and truthful connection refusal. This does not verify TUN.');
} finally { await application.close(); }
