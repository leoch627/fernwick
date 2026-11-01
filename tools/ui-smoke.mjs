import { chromium } from 'playwright-core';
import { createServer } from 'vite';
import { mkdir } from 'node:fs/promises';
import assert from 'node:assert/strict';
const server = await createServer({ server: { host: '127.0.0.1', port: 5173, strictPort: true } });
await server.listen();
const browser = await chromium.launch({ executablePath: process.env.STARRAIL_TEST_CHROMIUM || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 420, height: 700 }, deviceScaleFactor: 1, timezoneId: 'Asia/Shanghai' });
const failures = []; page.on('pageerror', error => failures.push(error.message));
await mkdir('work', { recursive: true });

// A UI-only bridge for states the browser preview never reaches; the shipped application has no fixture switch.
const fakeBridge = initial => {
  let state = initial; const listeners = new Set(); window.__commands = [];
  window.__set = change => { state = { ...state, ...change }; listeners.forEach(listener => listener(state)); };
  window.starrail = {
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    async command(command) {
      window.__commands.push(command.type);
      if (command.type === 'report') { window.__set({ report: { status: 'sending', code: null } }); state = { ...state, report: { status: 'sent', code: 'K7M3QX' } }; }
      if (command.type === 'login') state = { ...state, loggedIn: true };
      return { ok: true, state };
    },
  };
};

try {
  await page.goto('http://127.0.0.1:5173/');
  await page.getByRole('heading', { name: '未连接' }).waitFor();
  await page.getByText('预览', { exact: true }).waitFor();
  await page.screenshot({ path: 'work/preview-home.png', fullPage: true });

  // A new version is recommended on the home screen; one click downloads and installs it.
  const update = page.getByRole('region', { name: '推荐更新' });
  await update.getByText('新版本 0.3.0').waitFor();
  await update.getByRole('button', { name: '立即更新' }).click();
  await update.getByText('正在安装，完成后会自动重新打开').waitFor();
  assert.equal(await update.getByRole('button', { name: '立即更新' }).count(), 0);
  await page.screenshot({ path: 'work/preview-update.png' });

  // A refused connection explains itself under the button and offers the next step.
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await page.getByRole('status').filter({ hasText: '网络组件需要修复' }).waitFor();
  await page.getByRole('status').getByRole('button', { name: '修复' }).waitFor();
  assert.equal(await page.getByRole('heading', { name: '已连接' }).count(), 0);

  // Nodes are grouped by region with the flag drawn once; choosing one closes the list.
  await page.getByRole('button', { name: /线路 自动选择/ }).click();
  await page.getByRole('heading', { name: '选择线路' }).waitFor();
  await page.getByRole('heading', { name: /新加坡/ }).waitFor();
  assert.equal(await page.getByText(/^[0-9]+ ms$/).count(), 0);
  await page.getByRole('button', { name: /Singapore 01/ }).click();
  await page.getByRole('heading', { name: '选择线路' }).waitFor({ state: 'detached' });
  await page.getByText('Singapore 01', { exact: true }).waitFor();

  // Home: system proxy by default; TUN and ad blocking are one click away.
  assert.equal(await page.getByRole('radio', { name: '系统代理' }).getAttribute('aria-checked'), 'true');
  await page.getByRole('radio', { name: 'TUN 模式' }).click();
  assert.equal(await page.getByRole('radio', { name: 'TUN 模式' }).getAttribute('aria-checked'), 'true');
  await page.getByText(/第一次需要管理员授权/).waitFor();
  assert.equal(await page.getByRole('switch', { name: '广告拦截' }).getAttribute('aria-checked'), 'true');
  await page.getByRole('switch', { name: '广告拦截' }).click();
  assert.equal(await page.getByRole('switch', { name: '广告拦截' }).getAttribute('aria-checked'), 'false');
  await page.getByRole('radio', { name: '系统代理' }).click();
  await page.getByText(/不需要管理员授权/).waitFor();

  // Settings: global mode is a switch, and without an endpoint a report falls back to a file.
  await page.getByRole('button', { name: '设置' }).click();
  assert.equal(await page.getByRole('switch', { name: '自动检查更新' }).count(), 0); // update checks are not optional
  // Appearance follows the system; 亮色 (三月七) and 暗色 (黑塔) force one palette.
  assert.equal(await page.getByRole('radio', { name: '跟随系统' }).getAttribute('aria-checked'), 'true');
  await page.getByRole('radio', { name: '暗色' }).click();
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'dark');
  await page.getByRole('radio', { name: '跟随系统' }).click();
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'system');
  await page.getByRole('switch', { name: '全局代理' }).click();
  assert.equal(await page.getByRole('switch', { name: '全局代理' }).getAttribute('aria-checked'), 'true');
  await page.getByRole('button', { name: /上报问题/ }).click();
  await page.getByRole('button', { name: '导出诊断文件' }).waitFor();
  await page.getByRole('button', { name: '返回' }).click();

  await page.emulateMedia({ colorScheme: 'dark' });
  await page.waitForTimeout(400); // let colour transitions finish before the screenshot
  await page.screenshot({ path: 'work/preview-dark.png', fullPage: true });
  await page.setViewportSize({ width: 360, height: 640 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);

  const fixture = await page.evaluate(async () => (await (await import('/preview.ts')).previewBridge().command({ type: 'state' })).state);

  // Signed out: only the login form.
  const login = await browser.newPage({ viewport: { width: 420, height: 700 } });
  login.on('pageerror', error => failures.push(error.message));
  await login.addInitScript(fakeBridge, { ...fixture, loggedIn: false, account: null, nodes: [] });
  await login.goto('http://127.0.0.1:5173/');
  await login.getByRole('textbox', { name: '邮箱' }).fill('user@example.com');
  await login.getByLabel('密码').fill('secret');
  assert.equal(await login.getByRole('button', { name: '设置' }).count(), 0);
  await login.screenshot({ path: 'work/preview-login.png' });
  await login.getByRole('button', { name: '登录' }).click();
  await login.getByRole('heading', { name: '未连接' }).waitFor();
  await login.close();

  // Announcements are text only, renewal is prominent near expiry, updates install in one click,
  // and a problem report shows the code to give support.
  const other = await browser.newPage({ viewport: { width: 420, height: 700 } });
  other.on('pageerror', error => failures.push(error.message));
  await other.addInitScript(fakeBridge, {
    ...fixture, reportAvailable: true, announcement: '<img src=x onerror=alert(1)>公告只显示文本',
    account: { ...fixture.account, expiresAt: new Date(fixture.now + 2 * 86400000 - 60000).toISOString() },
    download: { status: 'ready', version: '0.2.0', received: 1000, total: 1000, error: null },
  });
  await other.goto('http://127.0.0.1:5173/');
  await other.getByRole('note').getByText('<img src=x onerror=alert(1)>公告只显示文本', { exact: true }).waitFor();
  assert.equal(await other.getByRole('note').locator('img').count(), 0);
  await other.getByText('剩余 2 天').waitFor();
  assert.match(await other.getByRole('region', { name: '套餐' }).getAttribute('class'), /warn/);
  await other.getByRole('region', { name: '推荐更新' }).getByText('已下载，更新时会短暂断开连接').waitFor();
  await other.getByRole('region', { name: '推荐更新' }).getByRole('button', { name: '立即更新' }).click();
  await other.getByRole('button', { name: '设置' }).click();
  await other.getByRole('button', { name: /上报问题/ }).click();
  await other.getByRole('textbox', { name: '问题描述' }).fill('连不上');
  await other.getByRole('button', { name: '发送' }).click();
  assert.equal(await other.getByLabel('问题编号').textContent(), 'K7M3QX');
  await other.screenshot({ path: 'work/preview-report.png' });
  assert.deepEqual((await other.evaluate(() => window.__commands)).filter(value => value !== 'state'), ['install-update', 'report']);
  await other.close();

  // Connected in system proxy mode shows the local port; a system proxy failure offers TUN.
  const proxied = await browser.newPage({ viewport: { width: 420, height: 700 } });
  proxied.on('pageerror', error => failures.push(error.message));
  await proxied.addInitScript(fakeBridge, { ...fixture, connection: 'Connected', proxyPort: 7890 });
  await proxied.goto('http://127.0.0.1:5173/');
  await proxied.getByText(/本机端口 7890/).waitFor();
  assert.equal(await proxied.getByRole('radio', { name: '系统代理' }).isDisabled(), false);
  await proxied.evaluate(() => window.__set({ connection: 'Disconnected', proxyPort: 0, error: 'SYSTEM_PROXY_FAILED' }));
  await proxied.getByRole('status').filter({ hasText: '没能设置系统代理' }).waitFor();
  await proxied.getByRole('status').getByRole('button', { name: '改用 TUN 模式' }).click();
  await proxied.waitForFunction(() => window.__commands.includes('connect'));
  assert.deepEqual((await proxied.evaluate(() => window.__commands)).filter(value => value !== 'state'), ['preferences', 'connect']);
  await proxied.close();

  // Windows shows the name in its own title bar, so the page does not repeat it. The update cannot be dismissed.
  const windows = await browser.newPage({ viewport: { width: 420, height: 700 }, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0' });
  windows.on('pageerror', error => failures.push(error.message));
  await windows.addInitScript(fakeBridge, fixture);
  await windows.goto('http://127.0.0.1:5173/');
  await windows.getByRole('button', { name: '设置' }).waitFor();
  assert.equal(await windows.locator('header.topbar').getByText(fixture.brand).count(), 0);
  await windows.getByRole('region', { name: '推荐更新' }).getByRole('button', { name: '立即更新' }).waitFor();
  assert.equal(await windows.getByRole('button', { name: '稍后提醒' }).count(), 0);
  await windows.screenshot({ path: 'work/preview-windows.png' });
  await windows.close();
  assert.equal(await page.locator('header.topbar').getByText(fixture.brand).count(), 1);

  assert.deepEqual(failures, []);
  console.log('UI smoke passed: connection refusal with next step, grouped node selection, tunnel and ad blocking switches, system proxy port and fallback, settings switches, report fallback, dark and narrow layouts, login, text-only announcements, renewal warning, home update card with one-click update, Windows title bar, 三月七/黑塔 appearance, and report code; no page errors.');
} finally { await browser.close(); await server.close(); }
