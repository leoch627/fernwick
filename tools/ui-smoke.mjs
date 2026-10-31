import { chromium } from 'playwright-core';
import { createServer } from 'vite';
import { mkdir } from 'node:fs/promises';
import assert from 'node:assert/strict';
const server = await createServer({ server: { host: '127.0.0.1', port: 5173, strictPort: true } });
await server.listen();
const browser = await chromium.launch({ executablePath: process.env.STARRAIL_TEST_CHROMIUM || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 1, timezoneId: 'Asia/Tokyo' });
const failures = []; page.on('pageerror', error => failures.push(error.message));
try {
  await page.goto('http://127.0.0.1:5173/');
  await page.getByRole('heading', { name: '连接概览' }).waitFor();
  await page.getByText('界面预览 · 当前账号和节点为示例数据，未接入代理网络').waitFor();
  await mkdir('work', { recursive: true });
  await page.screenshot({ path: 'work/preview-desktop.png', fullPage: true });
  await page.getByRole('button', { name: '连接网络', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: '网络组件尚未安装' }).waitFor();
  assert.equal(await page.getByText('连接已就绪', { exact: true }).count(), 0);
  await page.getByRole('button', { name: '节点列表' }).click();
  await page.getByRole('heading', { name: '选择你的线路' }).waitFor();
  await page.getByRole('button', { name: '测试前 10 项' }).click();
  await page.getByRole('alert').filter({ hasText: '网络组件尚未安装' }).waitFor();
  assert.equal(await page.getByText(/^[0-9]+ ms$/).count(), 0);
  await page.getByRole('textbox', { name: '搜索节点' }).fill('新加坡');
  await page.getByRole('button', { name: /新加坡 · 狮城 01/ }).click();
  await page.getByText('新加坡 · 狮城 01', { exact: true }).waitFor();
  await page.getByRole('button', { name: '全局模式', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: '全局模式', exact: true }).getAttribute('aria-pressed'), 'true');
  await page.getByRole('button', { name: '偏好设置' }).click();
  await page.getByRole('switch', { name: '启动后自动连接' }).click();
  assert.equal(await page.getByRole('switch', { name: '启动后自动连接' }).getAttribute('aria-checked'), 'true');
  await page.getByRole('combobox').last().selectOption('dark');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.getByRole('button', { name: '关闭对话框' }).click();
  await page.screenshot({ path: 'work/preview-dark.png', fullPage: true });
  await page.setViewportSize({ width: 480, height: 880 });
  await page.screenshot({ path: 'work/preview-narrow.png', fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  // Inject a UI-only bridge in this test page; the shipped application has no fixture switch for updates.
  const fixture = await page.evaluate(async () => (await (await import('/preview.ts')).previewBridge().command({ type: 'state' })).state);
  const updates = await browser.newPage({ viewport: { width: 1180, height: 900 }, timezoneId: 'Asia/Tokyo' });
  updates.on('pageerror', error => failures.push(error.message));
  await updates.addInitScript(initial => {
    let state = { ...initial, announcement: '<img src=x onerror=alert(1)>公告只显示文本', showTrafficSummary: false,
      download: { status: 'available', version: '0.2.0', received: 0, total: 1000, error: null } };
    const listeners = new Set(); window.__updateCommands = [];
    window.__testDownload = status => { state = { ...state, download: { ...state.download, status, received: status === 'ready' ? 1000 : 500 } }; listeners.forEach(listener => listener(state)); };
    window.starrail = {
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async command(command) {
        window.__updateCommands.push(command.type);
        if (command.type === 'download-update') window.__testDownload('downloading');
        if (command.type === 'pause-update') window.__testDownload('paused');
        if (command.type === 'cancel-update') { state = { ...state, download: { ...state.download, status: 'available', received: 0 } }; }
        return { ok: command.type !== 'install-update', state, ...(command.type === 'install-update' ? { error: 'COMPONENTS_UNAVAILABLE' } : {}) };
      },
    };
  }, fixture);
  await updates.goto('http://127.0.0.1:5173/');
  await updates.getByRole('note').getByText('<img src=x onerror=alert(1)>公告只显示文本', { exact: true }).waitFor();
  assert.equal(await updates.getByRole('note').locator('img').count(), 0);
  assert.equal(await updates.getByRole('progressbar', { name: '套餐流量用量' }).count(), 0);
  assert.equal(await updates.locator('.expiry-date').isVisible(), true);
  await updates.getByRole('button', { name: '偏好设置' }).click();
  await updates.getByRole('button', { name: '下载更新', exact: true }).click();
  assert.equal(await updates.getByRole('progressbar', { name: '更新下载进度' }).getAttribute('value'), '500');
  await updates.getByRole('button', { name: '暂停', exact: true }).click();
  await updates.getByRole('button', { name: '继续下载', exact: true }).click();
  await updates.evaluate(() => window.__testDownload('failed'));
  await updates.getByRole('button', { name: '重试下载', exact: true }).click();
  await updates.evaluate(() => window.__testDownload('ready'));
  await updates.screenshot({ path: 'work/preview-update.png', fullPage: true });
  await updates.getByRole('button', { name: '重启并安装', exact: true }).click();
  await updates.getByRole('alert').filter({ hasText: '网络组件尚未安装' }).waitFor();
  await updates.getByRole('button', { name: '取消下载', exact: true }).click();
  await updates.getByRole('button', { name: '下载更新', exact: true }).waitFor();
  assert.deepEqual((await updates.evaluate(() => window.__updateCommands)).filter(value => value !== 'state'), ['download-update', 'pause-update', 'download-update', 'download-update', 'install-update', 'cancel-update']);
  await updates.close();
  assert.deepEqual(failures, []);
  console.log('UI smoke passed: preview label, connection refusal, node search/selection, mode, settings, dark theme, narrow layout, text-only announcements, traffic visibility and download actions; no page errors.');
} finally { await browser.close(); await server.close(); }
