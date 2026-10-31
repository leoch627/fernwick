import type { AppView, ClientBridge } from '../shared/view';
import { defaultPreferences } from '../shared/schema';
/** Browser preview is visibly synthetic and has no connection implementation or access to credentials. */
export function previewBridge(): ClientBridge {
  let state: AppView = {
    brand: 'StarRail Network', version: '0.1.0', environment: 'test', demo: true, loggedIn: true,
    account: { email: 'pr***@example.invalid', planName: '标准套餐（示例）', expiryKind: 'finite', expiresAt: new Date(Date.now() + 19 * 86400000).toISOString(), quotaKind: 'finite', usedBytes: '31353261260', quotaBytes: '214748364800', observedAt: new Date().toISOString(), status: '示例套餐' },
    connection: 'Disconnected', selectedNode: null, actualNode: null, sync: 'Fresh', lastSync: Date.now(), usableUntil: Date.now() + 86400000, error: null,
    nodes: ['日本 · 东京 01', '新加坡 · 狮城 01', '香港 · 港岛 01', '美国 · 洛杉矶 01'].map((name, i) => ({ id: String(i).padStart(64, '0'), name, group: '示例节点', region: null, protocol: 'vless', compatible: true, reason: null, latency: null, probe: 'untested' })),
    preferences: { ...defaultPreferences }, storage: 'memory', helperReady: false, policy: '使用内置设置', announcement: null, update: '更新发布源尚未配置', manualUpdate: false, pendingRenewal: false, links: { website: true, renew: true, help: true }, now: Date.now(),
    download: { status: 'idle', version: null, received: 0, total: 0, error: null }, rules: '使用内置大陆分流规则', showTrafficSummary: true,
  };
  const listeners = new Set<(s: AppView) => void>();
  return {
    async command(command) {
      let error: AppView['error'] = null;
      if (command.type === 'preferences') state = { ...state, preferences: command.preferences, selectedNode: command.preferences.nodeId };
      if (command.type === 'connect' || command.type === 'repair' || command.type === 'probe-nodes') error = 'COMPONENTS_UNAVAILABLE';
      if (command.type === 'sync' || command.type === 'renewal-return') { state.lastSync = Date.now(); state.sync = 'Fresh'; }
      if (command.type === 'open-link' || command.type === 'diagnostics') error = 'CONFIGURATION_REQUIRED';
      if (command.type === 'logout') { state.loggedIn = false; state.account = null; state.nodes = []; }
      if (command.type === 'login') error = 'CONFIGURATION_REQUIRED';
      if (['download-update', 'install-update'].includes(command.type)) error = 'CONFIGURATION_REQUIRED';
      state = { ...state, now: Date.now(), error }; listeners.forEach(fn => fn(state)); return { ok: !error, state, ...(error ? { error } : {}) };
    },
    subscribe(fn) { listeners.add(fn); return () => { listeners.delete(fn); }; },
  };
}
