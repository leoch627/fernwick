import type { AppView, ClientBridge } from '../shared/view';
import { defaultPreferences } from '../shared/schema';
/** Browser preview is visibly synthetic and has no connection implementation or access to credentials. */
export function previewBridge(): ClientBridge {
  let state: AppView = {
    brand: 'StarRail Network', version: '0.1.0', environment: 'test', demo: true, loggedIn: true,
    account: { email: 'pr***@example.invalid', planName: '标准套餐（示例）', expiryKind: 'finite', expiresAt: new Date(Date.now() + 19 * 86400000).toISOString(), quotaKind: 'finite', usedBytes: '31353261260', quotaBytes: '214748364800', observedAt: new Date().toISOString(), status: '套餐可用' },
    connection: 'Disconnected', selectedNode: null, actualNode: null, sync: 'Fresh', lastSync: Date.now(), usableUntil: Date.now() + 86400000, error: null,
    nodes: [['🇯🇵 Tokyo 01', 'JP'], ['🇸🇬 Singapore 01', 'SG'], ['🇭🇰 Hong Kong 01', 'HK'], ['🇺🇸 Los Angeles 01', 'US']].map(([name, region], i) => ({ id: String(i).padStart(64, '0'), name: name!, group: '示例节点', region: region!, protocol: 'vless', compatible: true, reason: null, latency: null, probe: 'untested' as const })),
    preferences: { ...defaultPreferences }, storage: 'memory', helperReady: false, proxyPort: 0, policy: '使用内置设置', announcement: null, update: '发现新版本 0.3.0', manualUpdate: false, installing: false, pendingRenewal: false, links: { website: true, renew: true, help: true }, report: { status: 'idle', code: null }, reportAvailable: false, now: Date.now(),
    download: { status: 'available', version: '0.3.0', received: 0, total: 25165824, error: null }, rules: '使用内置大陆分流规则', showTrafficSummary: true,
  };
  const listeners = new Set<(s: AppView) => void>();
  const publish = (change: Partial<AppView>) => { state = { ...state, ...change, now: Date.now() }; listeners.forEach(fn => fn(state)); };
  // A pretend download, so the update card can be seen working; nothing is installed.
  let timer: ReturnType<typeof setInterval> | undefined;
  const download = (install: boolean) => {
    if (timer || state.download.status === 'ready') { if (install) publish({ installing: true, update: '正在安装更新，完成后会自动重新打开' }); return; }
    publish({ installing: install, download: { ...state.download, status: 'downloading' } });
    timer = setInterval(() => {
      const received = Math.min(state.download.total, state.download.received + state.download.total / 8);
      const done = received >= state.download.total;
      publish({ download: { ...state.download, received, status: done ? 'ready' : 'downloading' }, ...(done && state.installing ? { update: '正在安装更新，完成后会自动重新打开' } : {}) });
      if (done) { clearInterval(timer); timer = undefined; }
    }, 300);
  };
  return {
    async command(command) {
      let error: AppView['error'] = null;
      if (command.type === 'preferences') state = { ...state, preferences: command.preferences, selectedNode: command.preferences.nodeId };
      if (command.type === 'connect' || command.type === 'repair' || command.type === 'probe-nodes') error = 'COMPONENTS_UNAVAILABLE';
      if (command.type === 'sync' || command.type === 'renewal-return') { state.lastSync = Date.now(); state.sync = 'Fresh'; }
      if (command.type === 'open-link' || command.type === 'diagnostics') error = 'CONFIGURATION_REQUIRED';
      if (command.type === 'logout') { state.loggedIn = false; state.account = null; state.nodes = []; }
      if (command.type === 'login') error = 'CONFIGURATION_REQUIRED';
      if (command.type === 'install-update' || command.type === 'download-update') download(command.type === 'install-update');
      if (command.type === 'check-update') state.update = '发现新版本 0.3.0';
      state = { ...state, now: Date.now(), error }; listeners.forEach(fn => fn(state)); return { ok: !error, state, ...(error ? { error } : {}) };
    },
    subscribe(fn) { listeners.add(fn); return () => { listeners.delete(fn); }; },
  };
}
