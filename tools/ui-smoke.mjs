import { chromium } from 'playwright-core';
import { createServer } from 'vite';
import { mkdir } from 'node:fs/promises';
import assert from 'node:assert/strict';
const server = await createServer({ server: { host: '127.0.0.1', port: 5173, strictPort: true } });
await server.listen();
const browser = await chromium.launch({ executablePath: process.env.STARRAIL_TEST_CHROMIUM || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 420, height: 700 }, deviceScaleFactor: 1, timezoneId: 'Asia/Shanghai', userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36' });
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
      if (command.type === 'preferences') state = { ...state, preferences: { ...command.preferences, favoriteNodeIds: state.preferences.favoriteNodeIds, recentNodeIds: state.preferences.recentNodeIds }, selectedNode: command.preferences.nodeId };
      if (command.type === 'favorite-node') {
        const ids = state.preferences.favoriteNodeIds.filter(id => id !== command.nodeId);
        if (command.favorite) ids.push(command.nodeId);
        state = { ...state, preferences: { ...state.preferences, favoriteNodeIds: ids } };
      }
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
  await update.getByText('正在安装', { exact: true }).waitFor();
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
  await page.getByRole('button', { name: '收藏 Singapore 01', exact: true }).click();
  await page.getByRole('heading', { name: '选择线路' }).waitFor();
  await page.getByRole('tab', { name: '收藏 1', exact: true }).click();
  assert.equal(await page.locator('.node-row-wrap').count(), 1);
  await page.getByRole('textbox', { name: '搜索线路' }).fill('does-not-exist');
  await page.getByText('没有找到匹配的线路').waitFor();
  await page.getByRole('textbox', { name: '搜索线路' }).fill('');
  await page.screenshot({ path: 'work/preview-favorites.png' });
  await page.getByRole('button', { name: 'Singapore 01', exact: true }).click();
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

  // Recent connections preserve MRU order across regions, hide disappeared nodes,
  // and favorite actions never choose a node or connect.
  const lists = await browser.newPage({ viewport: { width: 360, height: 640 } });
  lists.on('pageerror', error => failures.push(error.message));
  const recentIds = [fixture.nodes[2].id, fixture.nodes[1].id, fixture.nodes[0].id];
  const listFixture = { ...fixture, nodes: fixture.nodes.map((node, i) => ({ ...node, region: i === 2 ? 'JP' : node.region })), preferences: { ...fixture.preferences, favoriteNodeIds: ['disappeared'], recentNodeIds: [...recentIds, 'disappeared'] } };
  await lists.addInitScript(fakeBridge, listFixture);
  await lists.goto('http://127.0.0.1:5173/');
  await lists.getByRole('button', { name: /^线路/ }).click();
  await lists.getByRole('tab', { name: '最近 3', exact: true }).click();
  assert.deepEqual(await lists.locator('.node-row-wrap .node-name strong').allTextContents(), ['Hong Kong 01', 'Singapore 01', 'Tokyo 01']);
  await lists.getByRole('button', { name: '收藏 Singapore 01', exact: true }).click();
  assert.equal(await lists.getByRole('heading', { name: '选择线路' }).count(), 1);
  assert.equal((await lists.evaluate(() => window.__commands)).includes('preferences'), false);
  assert.equal((await lists.evaluate(() => window.__commands)).includes('connect'), false);
  await lists.getByRole('tab', { name: '收藏 1', exact: true }).click();
  await lists.getByRole('button', { name: '取消收藏 Singapore 01', exact: true }).click();
  await lists.getByText('暂无收藏').waitFor();
  await lists.getByRole('tab', { name: '最近 3', exact: true }).click();
  assert.equal(await lists.evaluate(() => document.querySelector('dialog').scrollWidth <= innerWidth), true);
  await lists.screenshot({ path: 'work/preview-recent-narrow.png' });
  await lists.close();

  // Failed update checks are visible even before an artifact is selected.
  const recovery = await browser.newPage({ viewport: { width: 360, height: 640 } });
  recovery.on('pageerror', error => failures.push(error.message));
  await recovery.addInitScript(fakeBridge, { ...fixture, updateError: 'UPDATE_CHECK_FAILED', update: '无法连接更新服务器，请检查网络后重试。已打开手动下载页', download: { status: 'idle', version: null, received: 0, total: 0, error: null } });
  await recovery.goto('http://127.0.0.1:5173/');
  const recoveryCard = recovery.getByRole('region', { name: '推荐更新' });
  await recoveryCard.getByText('更新未完成', { exact: true }).waitFor();
  await recoveryCard.getByRole('button', { name: '手动下载', exact: true }).click();
  await recoveryCard.getByRole('button', { name: '重试', exact: true }).click();
  assert.deepEqual((await recovery.evaluate(() => window.__commands)).filter(type => type !== 'state'), ['open-download-page', 'check-update']);
  assert.equal(await recovery.getByRole('status').count(), 0);
  await recovery.screenshot({ path: 'work/preview-update-recovery.png' });
  await recovery.evaluate(() => window.__set({ error: 'SNAPSHOT_EXPIRED' }));
  await recovery.getByRole('status').getByRole('button', { name: '刷新线路' }).click();
  assert.equal((await recovery.evaluate(() => window.__commands)).at(-1), 'sync');
  await recovery.close();

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
  await other.getByRole('region', { name: '推荐更新' }).getByText('已下载', { exact: true }).waitFor();
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
  // Windows has no flag glyphs of its own; the bundled flag font draws them.
  assert.equal(await windows.evaluate(() => document.documentElement.classList.contains('country-flags')), true);
  await windows.getByRole('button', { name: /^线路/ }).click();
  await windows.getByRole('heading', { name: '选择线路' }).waitFor();
  assert.equal(await windows.evaluate(async () => { await document.fonts.load('20px "Country Flags"', '\u{1F1EF}\u{1F1F5}'); return document.fonts.check('20px "Country Flags"', '\u{1F1EF}\u{1F1F5}'); }), true);
  await windows.screenshot({ path: 'work/preview-windows-flags.png' });
  await windows.close();
  assert.equal(await page.evaluate(() => document.documentElement.classList.contains('country-flags')), true);
  assert.equal(await page.locator('header.topbar').getByText(fixture.brand).count(), 1);

  assert.deepEqual(failures, []);
  console.log('UI smoke passed: connection refusal with next step, grouped node selection, tunnel and ad blocking switches, system proxy port and fallback, settings switches, report fallback, dark and narrow layouts, login, text-only announcements, renewal warning, home update card with one-click update, Windows title bar, 三月七/黑塔 appearance, and report code; no page errors.');
} catch (error) {
  await page.screenshot({ path: 'work/preview-test-failure.png', fullPage: true }).catch(() => {});
  console.error('UI at failure:', await page.locator('body').innerText().catch(() => 'unavailable'), failures);
  throw error;
} finally { await browser.close(); await server.close(); }
