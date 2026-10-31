import React, { useEffect, useRef, useState, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import type { AppView, ClientBridge } from '../shared/view';
import type { Command, Preferences } from '../shared/schema';
import { messages } from '../shared/errors';
import { previewBridge } from './preview';
import './style.css';
declare global { interface Window { starrail?: ClientBridge; } }
const bridge = window.starrail ?? previewBridge();
function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    power: <><path d="M12 3v9"/><path d="M6.1 5.8a9 9 0 1 0 11.8 0"/></>,
    grid: <><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></>,
    nodes: <><circle cx="12" cy="5" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="18" r="3"/><path d="m10.5 7.5-4 8m7-8 4 8M8 18h8"/></>,
    settings: <><path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></>,
    globe: <><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/></>,
    shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z"/><path d="m8 12 3 3 5-6"/></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.2 6.2A8 8 0 0 1 20 12M4 12a8 8 0 0 0 13.8 5.8"/></>,
    arrow: <><path d="M5 12h14m-5-5 5 5-5 5"/></>,
    chevron: <path d="m9 5 7 7-7 7"/>,
    external: <><path d="M14 3h7v7m0-7L10 14"/><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/></>,
    help: <><circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 2-3 4m0 3h.01"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    close: <path d="m6 6 12 12M6 18 18 6"/>,
    search: <><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/></>,
    sparkle: <><path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5z"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    download: <><path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/></>,
    user: <><circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/></>,
    info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/></>,
    logout: <><path d="M9 3H4v18h5m5-5 4-4-4-4m-6 4h13"/></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.globe}</svg>;
}
function BrandMark() { return <svg width="37" height="37" viewBox="0 0 40 40" aria-hidden="true"><rect width="40" height="40" rx="12" fill="#6958df"/><path d="m21 7 2.5 10L34 20l-10.5 3L21 33l-3-10L8 20l10-3z" fill="white"/><path d="M7 29c9 3 23-8 26-17" stroke="#c4baff" strokeWidth="1.5" fill="none"/></svg>; }
const date = (value: string | number | null) => value ? new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }).format(new Date(value)) : '暂无数据';
function bytes(value: string | null) { if (value === null) return '待确认'; const n = BigInt(value); return `${Number(n * 10n / 1073741824n) / 10} GB`; }
function remaining(expires: string | null, now: number, kind: string) {
  if (kind === 'unlimited') return '长期有效'; if (!expires) return '待确认'; const diff = Date.parse(expires) - now;
  if (diff <= 0) return '已到期'; if (diff < 3600000) return `剩余 ${Math.ceil(diff / 60000)} 分钟`; if (diff < 86400000) return `剩余 ${Math.ceil(diff / 3600000)} 小时`; return `剩余 ${Math.ceil(diff / 86400000)} 天`;
}
function Modal({ title, children, close, wide = false }: { title: string; children: ReactNode; close(): void; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); return () => ref.current?.close(); }, []);
  return <dialog ref={ref} className={wide ? 'modal wide' : 'modal'} onCancel={close} onClick={event => { if (event.target === ref.current) close(); }}><header><div><span className="eyebrow">STAR RAIL / NETWORK</span><h2>{title}</h2></div><button className="icon-button" aria-label="关闭对话框" onClick={close}><Icon name="close"/></button></header>{children}</dialog>;
}
function App() {
  const [state, setState] = useState<AppView | null>(null); const [modal, setModal] = useState<'nodes' | 'settings' | null>(null);
  const [search, setSearch] = useState(''); const [busy, setBusy] = useState<string | null>(null); const [toast, setToast] = useState<string | null>(null);
  useEffect(() => { const unsubscribe = bridge.subscribe(setState); void bridge.command({ type: 'state' }).then(r => setState(r.state)).catch(() => setToast('无法连接桌面服务，请重新启动客户端')); return unsubscribe; }, []);
  useEffect(() => { if (state) document.documentElement.dataset.theme = state.preferences.theme; }, [state?.preferences.theme]);
  useEffect(() => { if (!toast) return; const id = setTimeout(() => setToast(null), 5000); return () => clearTimeout(id); }, [toast]);
  const run = async (command: Command) => { setBusy(command.type); try { const r = await bridge.command(command); setState(r.state); if (!r.ok && r.error) setToast(messages[r.error]); } catch { setToast('操作未完成，请重试'); } finally { setBusy(null); } };
  const prefs = (change: Partial<Preferences>) => { if (state) void run({ type: 'preferences', preferences: { ...state.preferences, ...change } }); };
  if (!state) return <div className="loading"><BrandMark/><p>{toast ?? '正在打开…'}</p></div>;
  const connected = state.connection === 'Connected'; const transitioning = !['Disconnected', 'Connected', 'RecoveryRequired'].includes(state.connection);
  const selected = state.nodes.find(n => n.id === state.selectedNode); const actual = state.nodes.find(n => n.id === state.actualNode);
  const expiry = remaining(state.account?.expiresAt ?? null, state.now, state.account?.expiryKind ?? 'unknown');
  const quota = state.account?.quotaBytes ? BigInt(state.account.quotaBytes) : 0n; const used = BigInt(state.account?.usedBytes ?? '0'); const percent = quota > 0n ? Math.min(100, Number(used * 10000n / quota) / 100) : 0;
  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><BrandMark/><div><strong>{state.brand}</strong></div></div>
      <div className="nav-label">工作空间</div>
      <nav aria-label="主导航">
        <button className={!modal ? 'nav active' : 'nav'} onClick={() => setModal(null)}><Icon name="grid"/>连接概览<span className="nav-dot"/></button>
        <button className={modal === 'nodes' ? 'nav active' : 'nav'} onClick={() => setModal('nodes')}><Icon name="nodes"/>节点列表<span className="nav-count">{state.nodes.length}</span></button>
        <button className={modal === 'settings' ? 'nav active' : 'nav'} onClick={() => setModal('settings')}><Icon name="settings"/>偏好设置</button>
      </nav>
      <div className="sidebar-bottom"><div className="sidebar-note"><span className="tiny-star">✦</span><strong>连接更远的世界</strong><p>规则分流，轻松连接。<br/>让网络回归简单。</p></div>
      <button className="nav" onClick={() => void run({ type: 'open-link', link: 'help' })}><Icon name="help"/>帮助中心<Icon name="external" size={14}/></button>
      <div className="version"><span className="status-dot"/>v{state.version}<span>{state.environment === 'test' ? '开发版本' : '正式版本'}</span></div></div>
    </aside>
    <main>
      <header className="topbar"><div className="breadcrumb">工作空间 <span>/</span> <b>连接概览</b></div><div className="account-chip"><span className="avatar"><Icon name="user" size={16}/></span><span>{state.account?.email ?? '尚未登录'}</span></div></header>
      <div className="content">
        {state.demo && <div className="demo-banner"><Icon name="info" size={16}/><span>界面预览 · 当前账号和节点为示例数据，未接入代理网络</span><span>PREVIEW</span></div>}
        {state.announcement && <div className="announcement" role="note"><Icon name="info" size={16}/><span>{state.announcement}</span></div>}
        <div className="page-title"><div><span className="eyebrow">YOUR CONNECTION, SIMPLIFIED</span><h1>连接概览<span className="title-star">✦</span></h1><p>选择你的线路，开始新的旅程。</p></div><button className="secondary refresh-button" disabled={!!busy || !state.loggedIn} onClick={() => void run({ type: 'sync' })}><Icon name="refresh" size={16}/> {state.sync === 'Syncing' ? '正在同步' : '刷新订阅'}</button></div>
        {state.error && <div className="error-banner" role="status"><Icon name="info" size={17}/><span>{messages[state.error]}{state.sync === 'UsingValidCache' ? '，正在使用上次有效数据。' : ''}</span><button onClick={() => state.error === 'COMPONENTS_UNAVAILABLE' ? setModal('settings') : void run({ type: 'sync' })}>{state.error === 'COMPONENTS_UNAVAILABLE' ? '查看详情' : '重试'}<Icon name="arrow" size={15}/></button></div>}
        <div className="dashboard-grid">
          <section className="card connection-card" aria-labelledby="connection-heading">
            <div className="card-top"><h2 id="connection-heading"><Icon name="shield" size={18}/>网络连接</h2><span className={`badge ${connected ? 'green' : ''}`}><span className="status-dot"/>{connected ? '已连接' : transitioning ? '处理中' : '未连接'}</span></div>
            {!state.loggedIn ? <form className="login-form" onSubmit={event => { event.preventDefault(); const form = event.currentTarget; const data = new FormData(form); const email = String(data.get('email')); const password = String(data.get('password')); form.reset(); void run({ type: 'login', email, password }); }}>
              <div className="login-symbol"><Icon name="sparkle" size={30}/></div><h3>欢迎来到 {state.brand}</h3><p>登录后，套餐与节点将自动同步。</p>
              <label>邮箱地址<input name="email" type="email" autoComplete="username" placeholder="you@example.com" required maxLength={254}/></label>
              <label>密码<input name="password" type="password" autoComplete="current-password" placeholder="输入账号密码" required maxLength={1024}/></label>
              <button className="primary" disabled={!!busy}>{busy === 'login' ? '正在登录…' : '登录并同步'}<Icon name="arrow" size={18}/></button>
              {state.demo && <small>浏览器预览不接受真实账号登录。</small>}
            </form> : <>
              <div className={`connection-visual ${connected ? 'connected' : ''}`}><div className="orbit orbit-one"/><div className="orbit orbit-two"/><span className="orbit-point p1"/><span className="orbit-point p2"/>
                <button className="power-button" aria-label={connected || transitioning ? '断开连接' : '连接网络'} onClick={() => void run({ type: connected || transitioning ? 'disconnect' : 'connect' })}><Icon name="power" size={40}/></button>
              </div><h3 className="connection-title">{connected ? '连接已就绪' : transitioning ? '正在准备连接' : '准备好，出发吧'}</h3><p className="connection-subtitle">{connected ? `当前线路：${actual?.name ?? '已验证节点'}` : '点击上方按钮，连接你的专属网络'}</p>
              <div className="mode-switch" role="group" aria-label="代理模式"><button aria-pressed={state.preferences.mode === 'rule'} className={state.preferences.mode === 'rule' ? 'selected' : ''} onClick={() => prefs({ mode: 'rule' })}><Icon name="shield" size={16}/>规则模式</button><button aria-pressed={state.preferences.mode === 'global'} className={state.preferences.mode === 'global' ? 'selected' : ''} onClick={() => prefs({ mode: 'global' })}><Icon name="globe" size={16}/>全局模式</button></div>
              <p className="mode-description">{state.preferences.mode === 'rule' ? '按规则分流，未命中流量通过代理' : '代理公网流量，保留系统必要例外'}</p>
              <button className="selected-node" onClick={() => setModal('nodes')}><span className="node-icon"><Icon name={selected ? 'globe' : 'sparkle'} size={22}/></span><span><small>当前选择</small><strong>{selected?.name ?? (state.selectedNode ? '节点已失效，请重新选择' : '自动选择最佳线路')}</strong></span><span className="node-status">{selected ? '未测试' : '自动'}</span><Icon name="chevron" size={17}/></button>
            </>}
          </section>
          <div className="right-column">
            <section className="card plan-card" aria-labelledby="plan-heading"><div className="card-top"><h2 id="plan-heading"><Icon name="sparkle" size={18}/>我的套餐</h2><span className="small-muted">{state.account?.status ?? '登录后查看'}</span></div><span className="plan-label">{state.account?.planName ?? '你的下一站，即将开启'}</span><div className="expiry"><strong>{expiry}</strong><span className="plan-orbit">✧</span></div><div className="expiry-date"><Icon name="clock" size={14}/>{state.account?.expiryKind === 'unknown' ? '到期时间暂不可用' : date(state.account?.expiresAt ?? null)}</div><div className="plan-divider"/>{state.showTrafficSummary && <><div className="traffic-label"><span>本周期用量</span><strong>{state.account ? bytes(state.account.usedBytes) : '—'} <span>/ {state.account?.quotaKind === 'unlimited' ? '不限流量' : state.account ? bytes(state.account.quotaBytes) : '—'}</span></strong></div><div className="progress" role="progressbar" aria-label="套餐流量用量" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${percent}%` }}/></div><p className="usage-note">用量以面板账单为准</p></>}<button className="renew-button" onClick={() => void run({ type: 'open-link', link: 'renew' })}>续费 / 管理套餐<Icon name="arrow" size={17}/></button><p className="renew-hint">{state.account?.email ?? '在官网登录你的账号'}{state.account ? ' · 续费时请核对账号' : ''}</p></section>
            <section className="card status-card"><div className="card-top"><h2><Icon name="refresh" size={17}/>同步状态</h2><span className="status-dot violet"/></div><div className="sync-line"><span>{state.sync === 'Fresh' ? '账号与节点已同步' : state.sync === 'Syncing' ? '正在同步账号与节点' : state.sync === 'UsingValidCache' ? '使用上次有效数据' : state.loggedIn ? '等待完整同步' : '登录后自动同步'}</span><span className="sync-check"><Icon name={state.sync === 'Fresh' ? 'check' : 'clock'} size={16}/></span></div><p className="small-muted">{state.lastSync ? date(state.lastSync) : '每次启动都会尝试刷新'}</p>{state.sync === 'UsingValidCache' && <p className="small-muted">可用至 {date(state.usableUntil)}</p>}{state.pendingRenewal && <button className="text-button" onClick={() => void run({ type: 'renewal-return' })}>已续费，刷新权益<Icon name="arrow" size={15}/></button>}</section>
          </div>
        </div>
        <div className="bottom-grid"><button className="shortcut card" onClick={() => void run({ type: 'open-link', link: 'website' })}><span className="shortcut-icon"><Icon name="globe"/></span><span><strong>探索 StarRail</strong><small>访问官网，了解更多服务</small></span><Icon name="external" size={16}/></button><button className="shortcut card" onClick={() => void run({ type: 'open-link', link: 'help' })}><span className="shortcut-icon blue"><Icon name="help"/></span><span><strong>需要一点帮助？</strong><small>查看使用指南与支持</small></span><Icon name="arrow" size={17}/></button></div>
        <footer><span><Icon name="shield" size={13}/> {state.helperReady ? '网络服务已就绪' : '首次连接将安装网络服务'}</span><span>STAR RAIL · STAY CONNECTED</span></footer>
      </div>
    </main>
    {modal === 'nodes' && <Modal title="选择你的线路" close={() => setModal(null)} wide><p className="modal-description">自动模式优先保留健康节点。手动选择不会自动切换地区。</p><div className="search-box"><Icon name="search" size={18}/><input aria-label="搜索节点" placeholder="搜索节点名称或分组" value={search} onChange={e => setSearch(e.target.value)}/></div><button className={`node-row auto-row ${!state.selectedNode ? 'node-selected' : ''}`} onClick={() => { prefs({ nodeId: null }); setModal(null); }}><span className="node-icon"><Icon name="sparkle"/></span><span><strong>自动选择</strong><small>最多探测 3 个合格候选</small></span>{!state.selectedNode && <Icon name="check"/>}</button><div className="list-heading"><span>可用线路 · {state.nodes.length} 个节点</span><button className="text-button" disabled={!!busy || !state.nodes.some(n => n.compatible)} onClick={() => void run({ type: 'probe-nodes', nodeIds: state.nodes.filter(n => n.compatible && `${n.name} ${n.group}`.toLowerCase().includes(search.toLowerCase())).slice(0, 10).map(n => n.id) })}>{busy === 'probe-nodes' ? '正在测试…' : '测试前 10 项'}</button></div><div className="node-list">{state.nodes.filter(n => `${n.name} ${n.group}`.toLowerCase().includes(search.toLowerCase())).map(n => <button key={n.id} className={`node-row ${state.selectedNode === n.id ? 'node-selected' : ''}`} disabled={!n.compatible} onClick={() => { prefs({ nodeId: n.id }); setModal(null); }}><span className="node-icon neutral"><Icon name="globe"/></span><span><strong>{n.name}</strong><small>{n.reason ?? `${n.protocol.toUpperCase()} · ${n.group}`}</small></span><span className="probe-label">{n.compatible ? n.probe === 'testing' ? '测试中' : n.probe === 'timeout' ? '未通过' : n.latency === null ? '未测试' : `${n.latency} ms` : '不兼容'}</span>{state.selectedNode === n.id && <Icon name="check" size={16}/>}</button>)}{!state.nodes.length && <div className="empty-state"><Icon name="nodes" size={32}/><p>暂无节点</p><small>登录并完成同步后，节点会出现在这里。</small></div>}</div><p className="drawer-note"><Icon name="info" size={14}/>每批最多 10 项，间隔 30 秒。探测仅验证 HTTPS；未测试不代表不可达。</p></Modal>}
    {modal === 'settings' && <Modal title="偏好设置" close={() => setModal(null)}><div className="settings-group"><div className="setting-row"><span><strong>开机启动</strong><small>登录系统后打开客户端</small></span><button role="switch" aria-checked={state.preferences.launchAtLogin} aria-label="开机启动" className={`toggle ${state.preferences.launchAtLogin ? 'on' : ''}`} onClick={() => prefs({ launchAtLogin: !state.preferences.launchAtLogin })}/></div><div className="setting-row"><span><strong>启动后自动连接</strong><small>完整同步或有效缓存通过门禁后连接</small></span><button role="switch" aria-checked={state.preferences.autoConnect} aria-label="启动后自动连接" className={`toggle ${state.preferences.autoConnect ? 'on' : ''}`} onClick={() => prefs({ autoConnect: !state.preferences.autoConnect })}/></div><label className="setting-row"><span><strong>关闭窗口时</strong><small>没有可靠托盘时始终确认退出</small></span><select value={state.preferences.closeBehavior} onChange={e => prefs({ closeBehavior: e.target.value as Preferences['closeBehavior'] })}><option value="tray">保留在托盘</option><option value="ask">询问是否退出</option></select></label><label className="setting-row"><span><strong>外观</strong><small>选择你喜欢的界面</small></span><select value={state.preferences.theme} onChange={e => prefs({ theme: e.target.value as Preferences['theme'] })}><option value="system">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></label></div><div className="settings-group"><div className="setting-row"><span><strong>客户端更新</strong><small>{state.update}</small></span><button className="secondary" onClick={() => void run({ type: 'check-update' })} disabled={!!busy}>检查更新</button></div>{state.download.status !== 'idle' && <div className="update-panel"><div className="update-meta"><strong>版本 {state.download.version}</strong><span>{Math.round(state.download.received / Math.max(1, state.download.total) * 100)}%</span></div>{!state.manualUpdate && <progress aria-label="更新下载进度" max={state.download.total || 1} value={state.download.received}/>}<p>{state.manualUpdate ? '此版本未做平台代码签名，需要从下载页手动安装。' : state.download.error ?? (state.download.status === 'ready' ? '下载完整，哈希已校验。安装会先断开连接。' : state.download.status === 'verifying' ? '正在校验下载文件…' : '下载可能使用计费流量，由你选择开始或继续。')}</p><div className="update-actions">{['available', 'paused', 'failed'].includes(state.download.status) && <button className="secondary" onClick={() => void run({ type: 'download-update' })}>{state.manualUpdate ? '打开下载页' : state.download.status === 'available' ? '下载更新' : state.download.status === 'failed' ? '重试下载' : '继续下载'}</button>}{state.download.status === 'downloading' && <button className="secondary" onClick={() => void run({ type: 'pause-update' })}>暂停</button>}{state.download.status === 'ready' && <button className="secondary" onClick={() => void run({ type: 'install-update' })}>重启并安装</button>}{state.download.status !== 'available' && <button className="secondary" onClick={() => void run({ type: 'cancel-update' })}>取消下载</button>}</div></div>}<div className="setting-row"><span><strong>分流规则</strong><small>{state.rules}</small></span></div><div className="setting-row"><span><strong>网络组件</strong><small>{state.helperReady ? '系统服务已就绪' : '安装或修复时需要系统授权'}</small></span><button className="secondary" onClick={() => void run({ type: 'repair' })}>修复</button></div><div className="setting-row"><span><strong>本地诊断</strong><small>导出前确认内容，仅保存在本机</small></span><button className="secondary" onClick={() => void run({ type: 'diagnostics' })}><Icon name="download" size={15}/>导出</button></div></div><div className="storage-note"><Icon name="shield" size={16}/><span>{state.storage === 'encrypted' ? '账号与节点秘密由系统安全存储加密保护。' : state.storage === 'locked' ? '安全存储已锁定；旧密文保留，请解锁后重启。' : '当前为内存会话。未使用明文保存秘密，重启后需重新登录。'}</span></div>{state.loggedIn && <button className="logout-button" onClick={() => { setModal(null); void run({ type: 'logout' }); }}><Icon name="logout" size={17}/>退出账号</button>}</Modal>}
    {toast && <div className="toast" role="alert"><Icon name="info" size={18}/><span>{toast}</span><button className="icon-button" aria-label="关闭提示" onClick={() => setToast(null)}><Icon name="close" size={16}/></button></div>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
