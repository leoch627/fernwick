import { app, BrowserWindow, ipcMain, dialog, shell, safeStorage, powerMonitor, Tray, Menu, nativeImage, Notification } from 'electron';
import { readFile, mkdir, writeFile, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { z } from 'zod';
import { validateBuild } from '../domain/trust';
import { strictJson } from '../domain/json';
import { PersistedSchema } from '../domain/persisted';
import { PreferencesSchema } from '../shared/schema';
import { AppError } from '../shared/errors';
import { JsonStore, SecureStore, atomicWrite } from '../services/storage';
import { NativeDriver, HelperTransport, type NativeManifest } from '../platform/native';
import { ContractSchema, V2BoardAdapter } from '../services/panel';
import { parseInWorker } from '../services/parser';
import { ClientController } from './controller';
import { DemoPanel } from './demo';
import type { PolicyRecord, Watermark } from '../services/policy';
import { CoreRuntime } from '../platform/core';
import { ArtifactDownload } from '../services/download';
import { ExpiryReminders, ReminderStateSchema } from '../services/reminders';
import { ResourceCoordinator, ResourceCacheSchema } from '../services/resource-coordinator';
import { RulesSchema } from '../domain/compiler';
import { NetworkEvents } from '../platform/network-events';
import { osVersionAtLeast } from '../services/update';
const recordSchema = z.object({ envelope: z.string().max(262144), watermark: z.object({ version: z.number().int().positive().safe(), hash: z.string().regex(/^[a-f0-9]{64}$/) }).strict() }).strict();
async function boot() {
  const build = validateBuild(strictJson(await readFile(join(__dirname, '../build-config.json'), 'utf8')));
  const contract = ContractSchema.parse(strictJson(await readFile(join(__dirname, '../adapter-contract.json'), 'utf8')));
  app.setName(build.name); app.setPath('userData', join(app.getPath('appData'), build.appId));
  if (!app.requestSingleInstanceLock()) { app.quit(); return; }
  await app.whenReady();
  const userData = app.getPath('userData');
  const nativeManifest = JSON.parse(await readFile(join(__dirname, '../native-manifest.json'), 'utf8')) as NativeManifest;
  let activeController: ClientController | null = null;
  const native = new NativeDriver(build, nativeManifest, app.isPackaged ? process.resourcesPath : join(__dirname, '../../resources'), process.platform === 'darwin' ? dirname(dirname(dirname(process.execPath))) : dirname(process.execPath), app.isPackaged, code => { void activeController?.nativeFailure(code); });
  await native.initialize();
  const http = new HelperTransport(native);
  const demo = !app.isPackaged && build.environment === 'test' && process.argv.includes('--demo');
  const dataRoot = demo ? join(userData, 'explicit-demo') : userData;
  const secure = new SecureStore(join(dataRoot, 'session.enc'), {
    available: () => safeStorage.isEncryptionAvailable() && !(process.platform === 'linux' && ['basic_text', 'unknown'].includes(safeStorage.getSelectedStorageBackend())),
    encrypt: text => safeStorage.encryptString(text), decrypt: bytes => safeStorage.decryptString(bytes),
  }, raw => PersistedSchema.parse(raw));
  let window: BrowserWindow | null = null; let tray: Tray | null = null; let quitting = false; let closedTip = false;
  const reminderStore = new JsonStore(join(dataRoot, 'reminders.json'), raw => ReminderStateSchema.parse(raw));
  const reminders = new ExpiryReminders(build.tenantId, state => reminderStore.save(state), async remaining => {
    if (demo || !Notification.isSupported()) return;
    const text = remaining <= 0 ? '套餐已到期，请前往官网查看。' : remaining < 86400000 ? `套餐将在 ${Math.ceil(remaining / 3600000)} 小时内到期。` : `套餐将在 ${Math.ceil(remaining / 86400000)} 天内到期。`;
    const notification = new Notification({ title: build.name, body: text, silent: true }); notification.on('click', () => window?.show()); notification.show();
  });
  try { const saved = await reminderStore.load(); if (saved) reminders.restore(saved); } catch { /* Reminders must not block account or network cleanup. */ }
  let osVersion = process.getSystemVersion(); let supportedDistribution = true;
  if (process.platform === 'linux') { try { const release = await readFile('/etc/os-release', 'utf8'); supportedDistribution = /^ID=(?:"ubuntu"|ubuntu)$/m.test(release); osVersion = /^VERSION_ID="?([^"\n]+)"?$/m.exec(release)?.[1] ?? ''; } catch { supportedDistribution = false; } }
  const baseline = RulesSchema.parse(strictJson(await readFile(join(__dirname, '../rules/baseline.json'), 'utf8'), 33554432));
  const resources = new ResourceCoordinator(build, baseline, new JsonStore(join(dataRoot, 'rules.json'), raw => ResourceCacheSchema.parse(raw), 68157440), http);
  const controller = new ClientController({
    build, version: app.getVersion(), panel: demo ? new DemoPanel() : new V2BoardAdapter(build, contract, http), secure, http, demo,
    networkDriver: demo ? undefined : native,
    installer: { get ready() { return native.verified; }, install: async (artifact, path, envelope) => { await native.install(artifact, path, envelope); app.quit(); } },
    reminders, resources, download: new ArtifactDownload(join(dataRoot, 'updates'), build),
    osCompatible: minimum => supportedDistribution && osVersionAtLeast(osVersion, minimum),
    confirmInstall: async version => (await dialog.showMessageBox({ type: 'question', title: '重启并安装更新', message: `安装 StarRail Network ${version}？`, detail: '将断开当前连接并开始系统安装。也可以稍后再安装。', buttons: ['重启并安装', '稍后'], cancelId: 1 })).response === 0,
    probe: async (node, signal) => {
      const coreRoot = app.isPackaged ? join(process.resourcesPath, 'native') : join(__dirname, '../../resources/native');
      return (await CoreRuntime.load(coreRoot, app.isPackaged ? nativeManifest : undefined)).probe(node, build.healthTargets, signal);
    },
    preferences: new JsonStore(join(dataRoot, 'preferences.json'), raw => PreferencesSchema.parse(raw)),
    policyStore: new JsonStore<PolicyRecord>(join(userData, 'policy.json'), raw => recordSchema.parse(raw)),
    releaseStore: new JsonStore<{ envelope: string; watermark: Watermark }>(join(userData, 'release-index.json'), raw => recordSchema.parse(raw)),
    parse: (raw, descriptor, signal) => parseInWorker(join(__dirname, 'parse-worker.cjs'), raw, { source: build.adapterId, capabilities: demo ? ['vless-tls'] : build.protocolCapabilities, confirmedTcpUdp: demo || build.nodeCapabilitiesConfirmed || (build.environment === 'test' && build.allowUnverifiedNodeTrials), authoritativeEmpty: descriptor.authoritativeEmpty }, signal),
    openExternal: async (url, hint) => {
      if (hint) { const answer = await dialog.showMessageBox({ type: 'info', title: '确认续费账号', message: `请确认网页中登录的是 ${hint}`, detail: '系统浏览器可能已登录其他账号。客户端不会自动同步网页登录状态。', buttons: ['打开网站', '取消'], cancelId: 1 }); if (answer.response !== 0) return false; }
      await shell.openExternal(url); return true;
    },
    exportDiagnostics: async report => {
      const confirmation = await dialog.showMessageBox({ type: 'info', title: '导出诊断', message: '仅导出版本、平台、时间、错误码与操作耗时。', detail: '不包含账号、订阅链接、节点凭据或访问记录；文件仅保存在本机。', buttons: ['选择保存位置', '取消'], cancelId: 1 }); if (confirmation.response !== 0) return;
      const result = await dialog.showSaveDialog({ title: '保存诊断文件', defaultPath: `starrail-diagnostics-${new Date().toISOString().slice(0, 10)}.json`, filters: [{ name: 'JSON', extensions: ['json'] }] });
      if (!result.canceled && result.filePath) await atomicWrite(result.filePath, JSON.stringify(report, null, 2));
    },
    launchAtLogin: async value => {
      if (!app.isPackaged) throw new AppError('CONFIGURATION_REQUIRED');
      if (process.platform === 'linux') {
        const folder = join(app.getPath('appData'), 'autostart'); const path = join(folder, `${build.appId}.desktop`);
        if (!value) { await rm(path, { force: true }); return; }
        await mkdir(folder, { recursive: true }); const executable = process.execPath.replace(/["\\`$]/g, '\\$&');
        await atomicWrite(path, `[Desktop Entry]\nType=Application\nName=StarRail Network\nExec="${executable}"\nX-GNOME-Autostart-enabled=true\n`);
      } else app.setLoginItemSettings({ openAtLogin: value });
    },
  });
  activeController = controller;
  const createWindow = async () => {
    window = new BrowserWindow({ width: 1180, height: 810, minWidth: 780, minHeight: 640, show: false, backgroundColor: '#f5f6fa', title: build.name,
      webPreferences: { preload: join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, spellcheck: false } });
    window.setMenuBarVisibility(false); window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    window.webContents.on('will-navigate', event => event.preventDefault()); window.webContents.on('will-attach-webview', event => event.preventDefault());
    window.webContents.session.setPermissionRequestHandler((_web, _permission, callback) => callback(false)); window.webContents.session.setPermissionCheckHandler(() => false);
    window.on('focus', () => void controller.command({ type: 'renewal-return' }));
    window.on('session-end', () => void controller.stop().catch(() => {}));
    window.on('close', event => {
      if (quitting) return; event.preventDefault();
      if (tray && controller.view().preferences.closeBehavior === 'tray') {
        window?.hide(); if (!closedTip) { closedTip = true; void dialog.showMessageBox({ message: 'StarRail Network 将继续在托盘中运行', detail: '通过托盘菜单可以重新打开窗口或退出客户端。' }); }
      } else void dialog.showMessageBox({ message: '退出 StarRail Network？', detail: '退出将断开连接并停止同步。', buttons: ['继续使用', '退出客户端'], cancelId: 0 }).then(answer => { if (answer.response === 1) app.quit(); });
    });
    window.once('ready-to-show', () => window?.show());
    if (!app.isPackaged && process.env.STARRAIL_DEV_UI === '1') await window.loadURL('http://127.0.0.1:5173');
    else await window.loadFile(join(__dirname, '../renderer/index.html'));
  };
  ipcMain.handle('starrail:intent', async (event, command: unknown) => {
    if (!window || event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame) throw new Error('Unauthorized IPC');
    return controller.command(command as never);
  });
  await createWindow();
  controller.subscribe(state => { if (window && !window.isDestroyed()) window.webContents.send('starrail:state', state); });
  if (process.platform !== 'linux') {
    try { tray = new Tray(nativeImage.createFromPath(join(__dirname, '../icon.png'))); tray.setToolTip(build.name); tray.setContextMenu(Menu.buildFromTemplate([{ label: '打开 StarRail Network', click: () => window?.show() }, { label: '断开连接', click: () => void controller.command({ type: 'disconnect' }) }, { type: 'separator' }, { label: '退出客户端', click: () => app.quit() }])); tray.on('click', () => window?.show()); } catch { tray = null; }
  }
  app.on('second-instance', () => { window?.show(); window?.focus(); });
  app.on('activate', () => window?.show());
  powerMonitor.on('resume', () => void controller.resume().catch(() => {}));
  powerMonitor.on('suspend', () => void controller.suspend().catch(() => {}));
  const networkEvents = new NetworkEvents(() => controller.networkChanged()); networkEvents.start();
  app.on('will-quit', () => networkEvents.stop());
  app.on('before-quit', event => {
    if (quitting) return; event.preventDefault();
    void controller.stop().then(() => { quitting = true; tray?.destroy(); app.quit(); }).catch(() => { void dialog.showErrorBox('网络恢复未确认', '请先恢复网络，或使用安装包提供的独立恢复入口。'); });
  });
  await controller.start();
  if (demo) await controller.command({ type: 'login', email: 'preview@example.invalid', password: 'demo' });
}
void boot().catch(() => { dialog.showErrorBox('StarRail Network 启动失败', '无法读取或验证本地配置，请使用完整安装包修复。'); app.exit(1); });
