import React, { useEffect, useRef, useState, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import type { AppView, ClientBridge, NodeView } from '../shared/view';
import type { Command, Preferences } from '../shared/schema';
import { messages, type ErrorCode } from '../shared/errors';
import { previewBridge } from './preview';
import { isWails, wailsBridge } from './wails';
import './style.css';
declare global { interface Window { starrail?: ClientBridge; } }
const bridge = window.starrail ?? (isWails() ? wailsBridge() : previewBridge());
/** Windows draws the app name and icon in its own title bar; the page does not repeat them. */
const nativeTitle = /Windows NT/.test(navigator.userAgent);

// One window, three things on it: connect, pick a node, see the plan. Everything else
// lives in the settings sheet. Most users never open it.

function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    power: <><path d="M12 3v9"/><path d="M6.1 5.8a9 9 0 1 0 11.8 0"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></>,
    chevron: <path d="m9 5 7 7-7 7"/>,
    back: <path d="m15 5-7 7 7 7"/>,
    check: <path d="m5 12 4 4L19 6"/>,
    close: <path d="m6 6 12 12M6 18 18 6"/>,
    search: <><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/></>,
    sparkle: <path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5z"/>,
    info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/></>,
    update: <><circle cx="12" cy="12" r="9"/><path d="M12 16.5v-9m-4 4 4-4 4 4"/></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.info}</svg>;
}
function BrandMark({ size = 32 }: { size?: number }) {
  // Drawn in the theme's two accents: pink to sky blue (三月七), lavender to violet (黑塔).
  return <svg width={size} height={size} viewBox="0 0 40 40" aria-hidden="true"><defs><linearGradient id="brand-mark" x1="0" y1="0" x2="1" y2="1"><stop offset="0" style={{ stopColor: 'var(--accent-2)' }}/><stop offset="1" style={{ stopColor: 'var(--accent)' }}/></linearGradient></defs><rect width="40" height="40" rx="12" fill="url(#brand-mark)"/><path d="m21 7 2.5 10L34 20l-10.5 3L21 33l-3-10L8 20l10-3z" style={{ fill: 'var(--on-accent)' }}/></svg>;
}

const regions: Record<string, string> = {
  HK: '香港', TW: '台湾', JP: '日本', SG: '新加坡', US: '美国', KR: '韩国', GB: '英国', DE: '德国', NL: '荷兰', FR: '法国', CA: '加拿大', AU: '澳大利亚',
  MO: '澳门', IN: '印度', RU: '俄罗斯', TR: '土耳其', MY: '马来西亚', TH: '泰国', VN: '越南', PH: '菲律宾', ID: '印尼', AR: '阿根廷', BR: '巴西', EU: '欧洲',
  IT: '意大利', ES: '西班牙', SE: '瑞典', CH: '瑞士', PL: '波兰', FI: '芬兰', IE: '爱尔兰', AE: '阿联酋', IL: '以色列', ZA: '南非', MX: '墨西哥', NZ: '新西兰',
};
const flag = (code: string | null) => code && /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : '🌐';
const regionName = (code: string | null) => code ? regions[code] ?? code : '其他';
/** Node names start with their flag; the flag is drawn separately. */
const label = (node: NodeView) => node.name.replace(/^\p{Regional_Indicator}{2}\s*/u, '') || node.name;
const latencyClass = (ms: number) => ms < 200 ? 'fast' : ms < 500 ? 'ok' : 'slow';

function remaining(expires: string | null, now: number, kind: string) {
  if (kind === 'unlimited') return { text: '长期有效', days: Infinity };
  if (!expires) return { text: '到期时间待确认', days: Infinity };
  const diff = Date.parse(expires) - now;
  if (diff <= 0) return { text: '已到期', days: 0 };
  if (diff < 86400000) return { text: `剩余 ${Math.ceil(diff / 3600000)} 小时`, days: 0 };
  return { text: `剩余 ${Math.ceil(diff / 86400000)} 天`, days: Math.ceil(diff / 86400000) };
}
const gb = (value: bigint) => `${Number(value * 10n / 1073741824n) / 10} GB`;

type Action = 'nodes' | 'renew' | 'repair' | 'report' | 'connect' | 'tun';
/** Problems in the words a user understands, each with the one thing to try next. */
const problems: Partial<Record<ErrorCode, { text: string; action?: Action }>> = {
  CONNECT_TIMEOUT: { text: '这条线路暂时连不上', action: 'nodes' },
  NO_COMPATIBLE_NODES: { text: '这条线路暂时用不了', action: 'nodes' },
  NO_AUTHORIZED_NODES: { text: '暂时没有可用线路', action: 'report' },
  ACCOUNT_EXPIRED: { text: '套餐已到期', action: 'renew' },
  QUOTA_EXHAUSTED: { text: '本期流量已用完', action: 'renew' },
  NO_SERVICE: { text: '账号还没有可用套餐', action: 'renew' },
  ACCOUNT_BANNED: { text: '账号暂不可用，请联系客服', action: 'report' },
  PERMISSION_REQUIRED: { text: '需要允许系统授权才能连接', action: 'connect' },
  COMPONENTS_UNAVAILABLE: { text: '网络组件需要修复', action: 'repair' },
  NETWORK_RECOVERY_REQUIRED: { text: '网络需要修复', action: 'repair' },
  SYSTEM_PROXY_FAILED: { text: '没能设置系统代理', action: 'tun' },
  NETWORK_CONFLICT: { text: '其他加速软件正在占用网络，请先关闭它' },
  CONTROL_UNAVAILABLE: { text: '暂时连不上服务器，请检查网络', action: 'report' },
  SNAPSHOT_EXPIRED: { text: '线路信息太久没更新，请检查网络', action: 'report' },
  CLOCK_UNTRUSTED: { text: '电脑时间不准，请校正后重试' },
  CANCELLED: { text: '已取消' },
};
const actionLabels: Record<Action, string> = { nodes: '换个线路', renew: '去续费', repair: '修复', report: '上报问题', connect: '重新连接', tun: '改用 TUN 模式' };
const problem = (code: ErrorCode) => problems[code] ?? { text: messages[code], action: 'report' as Action };

function Sheet({ title, children, close }: { title: string; children: ReactNode; close(): void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); return () => ref.current?.close(); }, []);
  return <dialog ref={ref} className="sheet" onCancel={close} aria-label={title}>
    <header><button className="icon-button" aria-label="返回" onClick={close}><Icon name="back"/></button><h2>{title}</h2><span/></header>
    <div className="sheet-body">{children}</div>
  </dialog>;
}

function Login({ state, busy, run }: { state: AppView; busy: string | null; run(command: Command): Promise<boolean> }) {
  return <main className="login">
    <BrandMark size={56}/><h1>{state.brand}</h1>
    <form onSubmit={event => {
      event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
      void run({ type: 'login', email: String(data.get('email')).trim(), password: String(data.get('password')) }).then(ok => { if (ok) form.reset(); });
    }}>
      <input name="email" type="email" aria-label="邮箱" autoComplete="username" placeholder="邮箱" required maxLength={254}/>
      <input name="password" type="password" aria-label="密码" autoComplete="current-password" placeholder="密码" required maxLength={1024}/>
      <button className="primary" disabled={!!busy}>{busy === 'login' ? '正在登录…' : '登录'}</button>
    </form>
    {state.links.website && <p className="login-links"><button className="link" onClick={() => void run({ type: 'open-link', link: 'website' })}>注册账号</button><span>·</span><button className="link" onClick={() => void run({ type: 'open-link', link: 'website' })}>忘记密码</button></p>}
    {state.demo && <p className="muted">预览模式不能登录真实账号</p>}
  </main>;
}

function NodeSheet({ state, close, run }: { state: AppView; close(): void; run(command: Command): Promise<boolean> }) {
  const [search, setSearch] = useState('');
  // Measure every node when the list opens; the core probes them in isolation.
  useEffect(() => {
    const ids = state.nodes.filter(n => n.compatible).slice(0, 64).map(n => n.id);
    if (ids.length) void bridge.command({ type: 'probe-nodes', nodeIds: ids }).catch(() => undefined);
  }, []);
  const choose = (nodeId: string | null) => { close(); void run({ type: 'preferences', preferences: { ...state.preferences, nodeId } }); };
  const visible = state.nodes.filter(n => !search || `${n.name} ${regionName(n.region)}`.toLowerCase().includes(search.toLowerCase()));
  const groups = new Map<string, NodeView[]>();
  for (const node of visible) groups.set(node.region ?? '', [...groups.get(node.region ?? '') ?? [], node]);
  return <Sheet title="选择线路" close={close}>
    <button className={`node-row auto ${state.selectedNode === null ? 'selected' : ''}`} onClick={() => choose(null)}>
      <span className="flag"><Icon name="sparkle"/></span><span className="node-name"><strong>自动选择</strong><small>推荐 · 一直使用最快的线路</small></span>
      {state.selectedNode === null && <Icon name="check" size={18}/>}
    </button>
    {state.nodes.length > 12 && <label className="search"><Icon name="search" size={16}/><input aria-label="搜索线路" placeholder="搜索地区或线路" value={search} onChange={e => setSearch(e.target.value)}/></label>}
    {[...groups].map(([region, nodes]) => <section key={region} className="node-group">
      <h3>{flag(region || null)} {regionName(region || null)}</h3>
      {nodes.map(node => <button key={node.id} className={`node-row ${state.selectedNode === node.id ? 'selected' : ''}`} disabled={!node.compatible} onClick={() => choose(node.id)}>
        <span className="node-name"><strong>{label(node)}</strong>{!node.compatible && <small>暂不可用</small>}</span>
        <span className={`latency ${node.latency !== null ? latencyClass(node.latency) : ''}`}>{node.probe === 'testing' ? '测速中' : node.latency !== null ? `${Math.round(node.latency)} ms` : node.probe === 'timeout' ? '超时' : ''}</span>
        {state.selectedNode === node.id && <Icon name="check" size={18}/>}
      </button>)}
    </section>)}
    {!state.nodes.length && <p className="empty">暂时没有线路，稍后会自动刷新</p>}
  </Sheet>;
}

function ReportPanel({ state, run }: { state: AppView; run(command: Command): Promise<boolean> }) {
  const [note, setNote] = useState(''); const [copied, setCopied] = useState(false);
  const { status, code } = state.report;
  if (status === 'sent' && code) return <div className="report sent">
    <p>问题编号</p><strong className="code" aria-label="问题编号">{code}</strong>
    <button className="secondary" onClick={() => { void navigator.clipboard?.writeText(code).then(() => setCopied(true)); }}>{copied ? '已复制' : '复制编号'}</button>
    <p className="muted">把编号发给客服，我们能看到你的连接情况</p>
  </div>;
  if (!state.reportAvailable) return <div className="report"><p className="muted">导出诊断文件后发给客服</p><button className="secondary" onClick={() => void run({ type: 'diagnostics' })}>导出诊断文件</button></div>;
  return <div className="report">
    <textarea aria-label="问题描述" placeholder="遇到了什么问题？（可以不填）" maxLength={500} value={note} onChange={e => setNote(e.target.value)} disabled={status === 'sending'}/>
    <button className="primary" disabled={status === 'sending'} onClick={() => void run({ type: 'report', note })}>{status === 'sending' ? '正在检查网络并上传…' : '发送'}</button>
    {status === 'failed' && <p className="warn">发送失败。可以导出诊断文件发给客服：<button className="link" onClick={() => void run({ type: 'diagnostics' })}>导出</button></p>}
    <p className="muted">会上传连接记录和网络检查结果，不包含浏览记录和密码</p>
  </div>;
}

function SettingsSheet({ state, busy, report, close, run, prefs }: { state: AppView; busy: string | null; report: boolean; close(): void; run(command: Command): Promise<boolean>; prefs(change: Partial<Preferences>): void }) {
  const [reporting, setReporting] = useState(report || state.report.status !== 'idle');
  const download = state.download;
  return <Sheet title="设置" close={close}>
    <div className="group">
      <div className="row appearance"><span><strong>外观</strong><small>亮色为三月七配色，暗色为黑塔配色</small></span>
        <div className="segmented" role="radiogroup" aria-label="外观">
          {([['system', '跟随系统'], ['light', '亮色'], ['dark', '暗色']] as const).map(([theme, name]) => <button key={theme} role="radio" aria-checked={state.preferences.theme === theme} className={state.preferences.theme === theme ? 'on' : ''} onClick={() => prefs({ theme })}>{name}</button>)}
        </div>
      </div>
    </div>
    <div className="group">
      <div className="row"><span><strong>开机自动启动</strong></span><button role="switch" aria-checked={state.preferences.launchAtLogin} aria-label="开机自动启动" className={`toggle ${state.preferences.launchAtLogin ? 'on' : ''}`} onClick={() => prefs({ launchAtLogin: !state.preferences.launchAtLogin })}/></div>
      <div className="row"><span><strong>全局代理</strong><small>一般不用打开。个别网站打不开时可以试试</small></span><button role="switch" aria-checked={state.preferences.mode === 'global'} aria-label="全局代理" className={`toggle ${state.preferences.mode === 'global' ? 'on' : ''}`} onClick={() => prefs({ mode: state.preferences.mode === 'global' ? 'rule' : 'global' })}/></div>
    </div>
    <div className="group">
      <button className="row" onClick={() => setReporting(!reporting)} aria-expanded={reporting}><span><strong>上报问题</strong><small>连不上、很慢时点这里</small></span><Icon name="chevron" size={16}/></button>
      {reporting && <ReportPanel state={state} run={run}/>}
    </div>
    <div className="group">
      <div className="row"><span><strong>自动检查更新</strong><small>打开时和每隔几小时检查一次，有新版本会显示在首页</small></span><button role="switch" aria-checked={state.preferences.autoUpdate} aria-label="自动检查更新" className={`toggle ${state.preferences.autoUpdate ? 'on' : ''}`} onClick={() => prefs({ autoUpdate: !state.preferences.autoUpdate })}/></div>
      <div className="row"><span><strong>检查更新</strong><small>{state.installing ? (download.status === 'downloading' ? `正在下载 ${Math.round(download.received / Math.max(1, download.total) * 100)}%` : '正在安装，完成后自动重新打开') : download.status === 'ready' ? `新版本 ${download.version} 已下载` : state.update}</small></span>
        {download.version && download.status !== 'idle' && !state.installing ? <button className="secondary" onClick={() => void run({ type: 'install-update' })}>{state.manualUpdate ? '去下载' : '立即更新'}</button>
          : <button className="secondary" disabled={!!busy || state.installing || download.status === 'downloading'} onClick={() => void run({ type: 'check-update' })}>检查</button>}
      </div>
      <div className="row"><span><strong>修复网络组件</strong><small>{state.preferences.tunnel === 'proxy' ? '系统代理模式用不到，TUN 模式才需要' : state.helperReady ? '组件正常' : '第一次连接时会自动安装'}</small></span><button className="secondary" disabled={!!busy} onClick={() => void run({ type: 'repair' })}>修复</button></div>
      {state.links.help && <button className="row" onClick={() => void run({ type: 'open-link', link: 'help' })}><span><strong>使用帮助</strong></span><Icon name="chevron" size={16}/></button>}
    </div>
    {state.loggedIn && <button className="danger" onClick={() => { close(); void run({ type: 'logout' }); }}>退出登录</button>}
    <p className="version">{state.brand} {state.version}{state.environment === 'test' ? ' · 测试版' : ''}</p>
  </Sheet>;
}

/** How traffic reaches the line, and ad blocking: the two switches people actually flip. */
function ModeCard({ state, working, prefs }: { state: AppView; working: boolean; prefs(change: Partial<Preferences>): void }) {
  const tun = state.preferences.tunnel === 'tun';
  const choose = (tunnel: Preferences['tunnel']) => { if (tunnel !== state.preferences.tunnel) prefs({ tunnel }); };
  return <section className="card mode-card" aria-label="连接方式">
    <div className="segmented" role="radiogroup" aria-label="连接方式">
      <button role="radio" aria-checked={!tun} className={tun ? '' : 'on'} disabled={working} onClick={() => choose('proxy')}>系统代理</button>
      <button role="radio" aria-checked={tun} className={tun ? 'on' : ''} disabled={working} onClick={() => choose('tun')}>TUN 模式</button>
    </div>
    <p className="muted">{tun ? '接管所有软件，包括游戏和命令行 · 第一次需要管理员授权'
      : `浏览器和大多数软件走代理 · 不需要管理员授权${state.proxyPort ? ` · 本机端口 ${state.proxyPort}` : ''}`}</p>
    <div className="row"><span><strong>广告拦截</strong></span><button role="switch" aria-checked={state.preferences.adBlock} aria-label="广告拦截" className={`toggle ${state.preferences.adBlock ? 'on' : ''}`} onClick={() => prefs({ adBlock: !state.preferences.adBlock })}/></div>
  </section>;
}

/** Clash Party style: a new version shows on the home screen and installs in one click. */
function UpdateCard({ state, run }: { state: AppView; run(command: Command): Promise<boolean> }) {
  const [later, setLater] = useState<string | null>(null);
  const { status, version, received, total, error } = state.download;
  if (!version || status === 'idle' || (later === version && !state.installing)) return null;
  const percent = Math.min(100, Math.round(received / Math.max(1, total) * 100));
  const downloading = status === 'downloading';
  const detail = state.manualUpdate ? '这个安装位置不能自动更新，请从官网下载'
    : state.installing ? (downloading ? `正在下载 ${percent}%` : '正在安装，完成后会自动重新打开')
    : status === 'failed' ? error ?? '下载没有完成，可以重试'
    : status === 'ready' ? '已下载，更新时会短暂断开连接'
    : '不用重新下载安装包，更新后自动重新打开';
  return <section className="card update-card" aria-label="推荐更新">
    <span className="update-icon"><Icon name="update"/></span>
    <span className="update-text">
      <span className="update-title"><span className="update-badge">推荐更新</span><strong>新版本 {version}</strong></span>
      <small aria-live="polite">{detail}</small>
      {state.installing && <span className="progress" role="progressbar" aria-label="更新进度" aria-valuenow={downloading ? percent : 100} aria-valuemin={0} aria-valuemax={100}><span className={downloading ? '' : 'indeterminate'} style={{ width: `${downloading ? percent : 100}%` }}/></span>}
    </span>
    {!state.installing && <>
      <button className="primary small" onClick={() => void run({ type: 'install-update' })}>{state.manualUpdate ? '去下载' : status === 'failed' ? '重试' : '立即更新'}</button>
      <button className="icon-button" aria-label="稍后提醒" title="稍后提醒" onClick={() => setLater(version)}><Icon name="close" size={16}/></button>
    </>}
  </section>;
}

function Home({ state, busy, run, open, prefs }: { state: AppView; busy: string | null; run(command: Command): Promise<boolean>; open(sheet: 'nodes' | 'settings', report?: boolean): void; prefs(change: Partial<Preferences>): void }) {
  const connected = state.connection === 'Connected';
  const working = ['Preparing', 'Connecting', 'Switching', 'Reconnecting', 'Disconnecting'].includes(state.connection) || busy === 'connect';
  const recovery = state.connection === 'RecoveryRequired';
  const selected = state.nodes.find(n => n.id === state.selectedNode);
  const actual = state.nodes.find(n => n.id === state.actualNode);
  const shown = selected ?? (connected ? actual : undefined);
  const account = state.account;
  const left = remaining(account?.expiresAt ?? null, state.now, account?.expiryKind ?? 'unknown');
  const quota = account?.quotaKind === 'finite' && account.quotaBytes ? BigInt(account.quotaBytes) : 0n;
  const used = BigInt(account?.usedBytes ?? '0');
  const percent = quota > 0n ? Math.min(100, Number(used * 1000n / quota) / 10) : 0;
  const issue = state.error && !connected ? problem(state.error) : null;
  const renewSoon = !!account && (left.days <= 7 || percent >= 90 || issue?.action === 'renew');
  const act = (action: Action) => {
    if (action === 'nodes') open('nodes'); else if (action === 'report') open('settings', true);
    else if (action === 'renew') void run({ type: 'open-link', link: 'renew' });
    else if (action === 'repair') void run({ type: 'repair' });
    else if (action === 'tun') void run({ type: 'preferences', preferences: { ...state.preferences, tunnel: 'tun' } }).then(ok => { if (ok) void run({ type: 'connect' }); });
    else void run({ type: 'connect' });
  };
  const toggle = () => void run({ type: recovery ? 'repair' : connected || working ? 'disconnect' : 'connect' });
  return <main className="home">
    <UpdateCard state={state} run={run}/>
    {state.announcement && <p className="announcement" role="note">{state.announcement}</p>}
    <section className={`power ${connected ? 'on' : working ? 'working' : ''}`}>
      <button className="power-button" aria-label={connected || working ? '断开连接' : recovery ? '修复网络' : '连接'} onClick={toggle}><Icon name="power" size={48}/></button>
      <h1 aria-live="polite">{connected ? '已连接' : working ? (state.connection === 'Disconnecting' ? '正在断开…' : '正在连接…') : recovery ? '网络需要修复' : '未连接'}</h1>
      {issue ? <p className="problem" role="status">{issue.text}{issue.action && <button className="link" onClick={() => act(issue.action!)}>{actionLabels[issue.action]}</button>}</p>
        : <p className="muted">{connected ? (state.preferences.mode === 'global' ? '全局代理' : '智能分流 · 国内网站不受影响') : working ? (state.preferences.tunnel === 'tun' && !state.helperReady ? '第一次使用 TUN 需要管理员授权' : '请稍候') : '点击按钮开始'}</p>}
    </section>
    <button className="card node-card" onClick={() => open('nodes')}>
      <span className="flag">{shown ? flag(shown.region) : <Icon name="sparkle"/>}</span>
      <span className="node-name"><small>线路</small><strong>{shown ? label(shown) : state.selectedNode ? '原线路已下线，请重新选择' : '自动选择'}</strong></span>
      {shown?.latency != null && <span className={`latency ${latencyClass(shown.latency)}`}>{Math.round(shown.latency)} ms</span>}
      <Icon name="chevron" size={18}/>
    </button>
    <ModeCard state={state} working={working} prefs={prefs}/>
    {account && <section className={`card plan-card ${renewSoon ? 'warn' : ''}`} aria-label="套餐">
      <div className="plan-line"><strong>{left.text}</strong>{quota > 0n && state.showTrafficSummary && <span>已用 {gb(used)} / {gb(quota)}</span>}</div>
      {quota > 0n && state.showTrafficSummary && <div className="progress" role="progressbar" aria-label="流量用量" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${percent}%` }}/></div>}
      <div className="plan-line"><small>{account.planName}</small>
        {state.links.renew && <button className={renewSoon ? 'primary small' : 'link'} onClick={() => void run({ type: 'open-link', link: 'renew' })}>续费</button>}</div>
      {state.pendingRenewal && <button className="link" onClick={() => void run({ type: 'renewal-return' })}>已经续费？点这里刷新</button>}
    </section>}
  </main>;
}

function App() {
  const [state, setState] = useState<AppView | null>(null); const [sheet, setSheet] = useState<'nodes' | 'settings' | null>(null);
  const [busy, setBusy] = useState<string | null>(null); const [toast, setToast] = useState<string | null>(null); const [report, setReport] = useState(false);
  useEffect(() => { const unsubscribe = bridge.subscribe(setState); void bridge.command({ type: 'state' }).then(r => setState(r.state)).catch(() => setToast('客户端没有正常启动，请重新打开')); return unsubscribe; }, []);
  useEffect(() => { if (state) document.documentElement.dataset.theme = state.preferences.theme; }, [state?.preferences.theme]);
  useEffect(() => { if (!toast) return; const id = setTimeout(() => setToast(null), 5000); return () => clearTimeout(id); }, [toast]);
  const run = async (command: Command) => {
    setBusy(command.type);
    try {
      const r = await bridge.command(command); setState(r.state);
      // Connection problems are shown under the button with what to do next.
      if (!r.ok && r.error && command.type !== 'connect' && command.type !== 'report') setToast(problem(r.error).text);
      return r.ok;
    } catch { setToast('操作没有完成，请重试'); return false; } finally { setBusy(null); }
  };
  const prefs = (change: Partial<Preferences>) => { if (state) void run({ type: 'preferences', preferences: { ...state.preferences, ...change } }); };
  const open = (next: 'nodes' | 'settings', reportOpen = false) => { setReport(reportOpen); setSheet(next); };
  if (!state) return <div className="loading"><BrandMark size={48}/><p>{toast ?? '正在打开…'}</p></div>;
  return <div className="app">
    {state.loggedIn && <header className={`topbar ${nativeTitle ? 'compact' : ''}`}>{!nativeTitle && <span className="brand"><BrandMark size={24}/>{state.brand}</span>}{state.demo && <span className="chip">预览</span>}<button className="icon-button" aria-label="设置" onClick={() => open('settings')}><Icon name="settings"/></button></header>}
    {state.loggedIn ? <Home state={state} busy={busy} run={run} open={open} prefs={prefs}/> : <Login state={state} busy={busy} run={run}/>}
    {sheet === 'nodes' && <NodeSheet state={state} close={() => setSheet(null)} run={run}/>}
    {sheet === 'settings' && <SettingsSheet state={state} busy={busy} report={report} close={() => setSheet(null)} run={run} prefs={prefs}/>}
    {toast && <div className="toast" role="alert"><span>{toast}</span><button className="icon-button" aria-label="关闭提示" onClick={() => setToast(null)}><Icon name="close" size={16}/></button></div>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
