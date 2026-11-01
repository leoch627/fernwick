import type { Account, BuildConfig, Command, Preferences } from '../shared/schema';
import { defaultPreferences, CommandSchema } from '../shared/schema';
import type { AppView, CommandResult } from '../shared/view';
import { AppError, errorCode, messages, type ErrorCode } from '../shared/errors';
import type { Session, Snapshot, ParsedNodes, SubscriptionDescriptor } from '../domain/model';
import { snapshotGate, restriction, tightenSnapshot } from '../domain/authorization';
import { ConservativeClock, Budget, jitter } from '../domain/time';
import { eligible, selectNode, type ProbeResult } from '../domain/selection';
import type { PanelAdapter } from '../services/panel';
import { SyncCoordinator } from '../services/sync';
import { EndpointPool } from '../services/endpoints';
import { PolicyService, verifyEnvelope, type PolicyRecord } from '../services/policy';
import { NetworkController, UnavailableDriver, type NetworkDriver } from '../platform/network';
import { Diagnostics } from '../services/diagnostics';
import type { JsonStore, SecureStore } from '../services/storage';
import type { Persisted } from '../domain/persisted';
import type { Transport } from '../services/http';
import { requireSuccess } from '../services/http';
import { verifyRelease, ReleaseSchema, selectUpdate, installationGate, type ReleaseIndex, type Artifact } from '../services/update';
import type { ArtifactDownload } from '../services/download';
import type { ExpiryReminders } from '../services/reminders';
import type { ResourceCoordinator } from '../services/resource-coordinator';
import type { Watermark } from '../services/policy';
import { trustedUrl } from '../domain/trust';
export interface ControllerDeps {
  version?: string;
  build: BuildConfig; panel: PanelAdapter; secure: SecureStore<Persisted>; preferences: JsonStore<Preferences>;
  policyStore: JsonStore<PolicyRecord>; releaseStore: JsonStore<{ envelope: string; watermark: Watermark }>;
  parse(raw: string, descriptor: SubscriptionDescriptor, signal: AbortSignal): Promise<ParsedNodes>;
  http: Transport; openExternal(url: string, accountHint?: string): Promise<boolean>;
  exportDiagnostics(report: unknown): Promise<void>; launchAtLogin(value: boolean): Promise<void>;
  demo: boolean;
  probe(node: Snapshot['nodes'][number], signal: AbortSignal): Promise<ProbeResult>;
  download?: ArtifactDownload; reminders?: ExpiryReminders; resources?: ResourceCoordinator;
  osCompatible?(minimum: string): boolean;
  installer?: { readonly ready: boolean; install(artifact: Artifact, path: string, envelope: string): Promise<void> };
  confirmInstall?(version: string): Promise<boolean>;
  networkDriver?: NetworkDriver;
}
export class ClientController {
  private session: Session | null = null; private snapshot: Snapshot | null = null; private account: Account | null = null;
  private restrictions = new Set<ErrorCode>(); private preferences: Preferences = { ...defaultPreferences };
  private startupAttempted = false; private syncStatus: AppView['sync'] = 'Idle'; private error: ErrorCode | null = null;
  private clock = new ConservativeClock(); private pool: EndpointPool; private sync: SyncCoordinator;
  private network: NetworkController; private policy: PolicyService; private diagnostics = new Diagnostics();
  private listeners = new Set<(view: AppView) => void>(); private timer: ReturnType<typeof setInterval> | null = null;
  private loginBudget: Budget | null = null; private loginGeneration = 0;
  private lastManual = -Infinity; private renewalUntil = 0; private renewalRefresh = -Infinity;
  private nextFull = 0; private nextAccount = 0; private nextPolicy = 0; private nextUpdate = 0; private nextPersist = 0;
  private nextPrune = 0;
  private updateStatus = '尚未检查'; private policyBusy = false; private updateBusy = false; private publicAbort = new AbortController();
  private releaseWatermark: Watermark | null = null; private lastPolicyVersion: number | null = null;
  private releaseIndex: ReleaseIndex | null = null; private updateArtifact: Artifact | null = null;
  private releaseEnvelope: string | null = null;
  private installedRules: string | null = null; private recovery: Promise<void> | null = null; private suspended: { intent: boolean; generation: number } | null = null;
  private actualNode: string | null = null; private closing = false;
  private probeBudget: Budget | null = null; private lastProbeBatch = -Infinity;
  private probeResults = new Map<string, { fingerprint: string; latency: number | null; state: 'testing' | 'healthy' | 'timeout' }>();
  constructor(private deps: ControllerDeps) {
    deps.download?.onChange(() => this.emit()); deps.resources?.onChange(() => this.emit());
    this.pool = new EndpointPool(deps.build.apiEndpoints, () => this.clock.now());
    this.policy = new PolicyService(deps.build, record => deps.policyStore.save(record), () => this.clock.now());
    this.network = new NetworkController(deps.networkDriver ?? new UnavailableDriver(), () => this.emit());
    this.sync = new SyncCoordinator(deps.build, deps.panel, this.pool, {
      session: () => this.session, policy: () => this.policy.active, now: () => this.clock.now(), snapshot: () => this.snapshot,
      account: account => { this.account = account; if (this.snapshot) this.snapshot = tightenSnapshot(this.snapshot, this.maxAge, account); this.emit(); void this.persist().catch(() => this.fail('STORAGE_FAILED')); },
      restrict: code => this.restrict(code),
      commit: async (snapshot, signal) => {
        const generation = this.session?.generation;
        const current = () => !signal.aborted && !!generation && generation === this.session?.generation;
        if (!current()) throw new AppError('CANCELLED');
        snapshot = tightenSnapshot(snapshot, this.maxAge, this.account ?? undefined);
        const data = this.persisted(snapshot, [], snapshot.account); if (!data) throw new AppError('CANCELLED');
        await deps.secure.save(data, current); if (!current()) throw new AppError('CANCELLED');
        this.snapshot = snapshot; this.account = snapshot.account; this.restrictions.clear(); this.clock.revalidateAfterOnlineSync();
        for (const [id, result] of this.probeResults) if (!snapshot.nodes.some(n => n.id === id && n.connectionFingerprint === result.fingerprint)) this.probeResults.delete(id);
        // Policy may tighten the window during disk IO. Never expose the wider candidate.
        this.snapshot = tightenSnapshot(this.snapshot, this.maxAge); await this.persist();
        if (this.actualNode && !snapshot.nodes.some(n => n.id === this.actualNode)) await this.network.disconnect();
      },
      done: error => {
        this.startupAttempted = true; this.error = error;
        const gate = this.gate(); this.syncStatus = error ? gate ? gate === 'AUTH_INVALID' ? 'NeedsLogin' : this.restrictions.size ? 'Denied' : 'Unavailable' : 'UsingValidCache' : gate ? this.restrictions.size ? 'Denied' : 'Unavailable' : 'Fresh';
        this.diagnostics.record({ stage: 'sync', code: error ?? 'SYNC_COMPLETE' }); this.emit();
      }, parse: deps.parse,
    });
  }
  private get maxAge() { return this.policy.active?.refresh.maxSnapshotAgeSec ?? 86400; }
  private persisted(snapshot = this.snapshot, restrictions = [...this.restrictions], account = this.account): Persisted | null {
    return this.session ? { schemaVersion: 1, productId: this.deps.build.productId, environment: this.deps.build.environment, session: this.session, snapshot, account, restrictions, timeUpper: this.clock.highWater } : null;
  }
  private async persist() { const data = this.persisted(); const generation = this.session?.generation; if (data) await this.deps.secure.save(data, () => this.session?.generation === generation); }
  private fail(code: ErrorCode) { this.error = code; this.diagnostics.record({ stage: 'lifecycle', code }); this.emit(); }
  private restrict(code: ErrorCode) {
    this.probeBudget?.cancel();
    this.restrictions.add(code); this.error = code;
    if (code === 'AUTH_INVALID') { this.session = null; this.snapshot = null; this.account = null; this.probeResults.clear(); this.syncStatus = 'NeedsLogin'; this.sync.cancel(); void this.deps.secure.clear().catch(() => this.fail('STORAGE_FAILED')); }
    else void this.persist().catch(() => this.fail('STORAGE_FAILED'));
    void this.network.disconnect().catch(() => this.fail('NETWORK_RECOVERY_REQUIRED')); this.emit();
  }
  private gate(): ErrorCode | null {
    return snapshotGate({ build: this.deps.build, session: this.session, snapshot: this.snapshot, startupAttempted: this.startupAttempted, trustedTime: this.clock.trusted, now: this.clock.now(), restrictions: this.restrictions });
  }
  subscribe(listener: (view: AppView) => void) { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  private emit() { if (this.closing) return; const view = this.view(); this.listeners.forEach(l => l(view)); }
  view(): AppView {
    const active = this.policy.active; const a = this.account; const gate = this.gate();
    const mask = (email: string) => { const [name, domain] = email.split('@'); return `${name?.slice(0, 2)}***@${domain}`; };
    return {
      brand: this.deps.build.name, version: this.deps.version ?? '0.1.0', environment: this.deps.build.environment, demo: this.deps.demo, loggedIn: !!this.session,
      account: a ? { email: mask(a.email), planName: a.planName, expiryKind: a.expiryKind, expiresAt: a.expiresAt, quotaKind: a.quotaKind, usedBytes: a.usedBytes, quotaBytes: a.quotaBytes, observedAt: a.observedAt, status: restriction(a, this.clock.now()) ? messages[restriction(a, this.clock.now())!] : a.serviceAllowed === 'yes' ? '套餐可用' : '权益待验证' } : null,
      report: { status: 'idle', code: null }, reportAvailable: false,
      connection: this.network.state, selectedNode: this.preferences.nodeId, actualNode: this.actualNode,
      sync: this.syncStatus, lastSync: this.snapshot?.fullSyncCompletedAt ?? null, usableUntil: this.snapshot?.usableUntil ?? null,
      error: this.error ?? (this.session && this.startupAttempted ? gate : null),
      nodes: (this.snapshot?.nodes ?? []).filter(n => !active?.nodeOperations.find(o => o.nodeId === n.id)?.hiddenFromList || n.id === this.actualNode).map(n => {
        const saved = this.probeResults.get(n.id), result = saved?.fingerprint === n.connectionFingerprint ? saved : null;
        return { id: n.id, name: n.name, group: active?.nodeOperations.find(o => o.nodeId === n.id)?.group ?? n.group, region: n.region, protocol: n.protocol, compatible: eligible(n, active, false), reason: active?.nodeOperations.find(o => o.nodeId === n.id)?.disabledForConnection ? '运营暂时停用' : n.incompatibility, latency: result?.latency ?? null, probe: result?.state ?? 'untested' };
      }),
      preferences: { ...this.preferences }, storage: this.deps.secure.mode, helperReady: this.network.ready, proxyPort: 0,
      policy: active ? `已验证策略 v${active.policyVersion}` : '使用内置设置', announcement: active?.ui.announcement?.text ?? null,
      update: this.updateStatus, manualUpdate: this.manualUpdate, pendingRenewal: this.renewalUntil > this.clock.now(),
      download: this.deps.download?.view ?? { status: 'idle', version: null, received: 0, total: 0, error: null },
      rules: this.deps.resources?.status ?? '内置规则待配置', showTrafficSummary: active?.ui.showTrafficSummary ?? true,
      links: { website: !!this.link('website'), renew: !!this.link('renew'), help: !!this.link('help') }, now: this.clock.now(),
    };
  }
  async start() {
    await this.deps.networkDriver?.initialize?.();
    await this.deps.download?.prune();
    await this.deps.resources?.restore(); this.installedRules = this.deps.resources?.fingerprint ?? null;
    try { this.preferences = await this.deps.preferences.load() ?? { ...defaultPreferences }; } catch { this.fail('STORAGE_FAILED'); }
    try { const saved = await this.deps.policyStore.load(); if (saved) this.policy.restore(saved); } catch { this.fail('POLICY_INVALID'); }
    if (this.policy.active && this.policy.envelope) void this.deps.resources?.apply(this.policy.envelope);
    try { const saved = await this.deps.releaseStore.load(); if (saved) { const payload = ReleaseSchema.parse(verifyEnvelope(saved.envelope, this.deps.build.updateKeys, 'v2board-client-release-v1').payload); const v = verifyRelease(saved.envelope, this.deps.build, null, Date.parse(payload.issuedAt)); if (v.watermark.hash === saved.watermark.hash && v.watermark.version === saved.watermark.version) this.releaseWatermark = saved.watermark; } } catch { this.fail('UPDATE_VERIFY_FAILED'); }
    try {
      const saved = await this.deps.secure.load();
      if (saved && saved.productId === this.deps.build.productId && saved.environment === this.deps.build.environment) {
        this.session = saved.session; this.snapshot = saved.snapshot; this.account = saved.account; this.restrictions = new Set(saved.restrictions); this.clock = new ConservativeClock(saved.timeUpper);
        if (this.account) { const denied = restriction(this.account, this.clock.now()); if (denied) this.restrictions.add(denied); }
      }
    } catch (e) { this.fail(errorCode(e)); }
    await this.network.disconnect().catch(e => this.fail(errorCode(e))); this.diagnostics.record({ stage: 'startup', code: 'STARTUP_ATTEMPT' });
    const policy = this.checkPolicy(); const firstPolicy = new Budget(3000);
    try { await firstPolicy.run(() => policy); } catch { /* Public policy check is independently bounded. */ } finally { firstPolicy.dispose(); }
    if (this.session) await this.refresh(true);
    this.schedule(); this.timer = setInterval(() => void this.tick().catch(e => this.fail(errorCode(e))), 1000);
    void this.checkUpdate();
    if (this.preferences.autoConnect && !this.gate()) await this.connect().catch(e => this.fail(errorCode(e)));
    this.emit();
  }
  private schedule() {
    const now = performance.now(), refresh = this.policy.active?.refresh;
    this.nextFull = now + jitter(refresh?.subscriptionIntervalSec ?? 1800); this.nextAccount = now + jitter(refresh?.accountIntervalSec ?? 300);
    this.nextPolicy = now + jitter(refresh?.policyIntervalSec ?? 900); this.nextUpdate = now + (this.policy.active?.update.checkIntervalSec ?? 21600) * 1000; this.nextPersist = now + 60000; this.nextPrune = now + 3600000;
  }
  private async tick() {
    const now = this.clock.now(); const monotonic = performance.now();
    this.deps.networkDriver?.setAuthorizedUntil?.(this.gate() ? 0 : this.snapshot?.usableUntil ?? 0);
    if (this.session && this.account && !this.deps.demo) { const generation = this.session.generation; void this.deps.reminders?.check(this.account, this.policy.active?.ui.expiryReminderDays ?? [7, 3], now, () => generation === this.session?.generation && !this.closing).catch(() => this.fail('STORAGE_FAILED')); }
    const rules = this.deps.resources?.fingerprint ?? null;
    if (rules !== this.installedRules) { this.installedRules = rules; if (this.network.desiredConnected) void this.networkChanged(false); }
    if (this.gate() || this.maintenance(now)) this.probeBudget?.cancel();
    if (this.network.desiredConnected && (this.gate() || this.maintenance(now))) await this.network.disconnect();
    if ((this.policy.active?.policyVersion ?? null) !== this.lastPolicyVersion) {
      this.probeBudget?.cancel();
      this.lastPolicyVersion = this.policy.active?.policyVersion ?? null;
      if (this.snapshot) { this.snapshot = tightenSnapshot(this.snapshot, this.maxAge); await this.persist(); }
      if (this.actualNode && this.snapshot) { const actual = this.snapshot.nodes.find(n => n.id === this.actualNode); if (!actual || !eligible(actual, this.policy.active, false)) await this.network.disconnect(); }
    }
    if (this.session && (monotonic >= this.nextFull || this.snapshot && now >= this.snapshot.usableUntil - 60000 && monotonic >= this.nextAccount)) {
      this.nextFull = monotonic + jitter(this.policy.active?.refresh.subscriptionIntervalSec ?? 1800); this.nextAccount = monotonic + jitter(this.policy.active?.refresh.accountIntervalSec ?? 300); void this.refresh(true);
    } else if (this.session && monotonic >= this.nextAccount) { this.nextAccount = monotonic + jitter(this.policy.active?.refresh.accountIntervalSec ?? 300); void this.refresh(false); }
    if (monotonic >= this.nextPolicy) { this.nextPolicy = monotonic + jitter(this.policy.active?.refresh.policyIntervalSec ?? 900); void this.checkPolicy(); }
    if (monotonic >= this.nextUpdate) { this.nextUpdate = monotonic + (this.policy.active?.update.checkIntervalSec ?? 21600) * 1000; void this.checkUpdate(); }
    if (monotonic >= this.nextPersist) { this.nextPersist = monotonic + 60000; await this.persist(); }
    if (monotonic >= this.nextPrune) { this.nextPrune = monotonic + 3600000; await this.deps.download?.prune(); }
    this.emit();
  }
  private maintenance(now: number) { const m = this.policy.active?.maintenance; return !!m && m.platforms.includes(process.platform as 'linux') && Date.parse(m.startsAt) <= now && Date.parse(m.endsAt) > now; }
  private async refresh(full: boolean) { if (!this.session) return; this.syncStatus = 'Syncing'; this.emit(); await this.sync.request(full); }
  private async probeNodes(ids: string[]) {
    const denied = this.gate(); if (denied) throw new AppError(denied);
    if (this.deps.demo || this.deps.build.healthTargets.length < 2) throw new AppError('COMPONENTS_UNAVAILABLE');
    if (this.probeBudget || performance.now() - this.lastProbeBatch < 30000) throw new AppError('RATE_LIMITED');
    const nodes = [...new Set(ids)].map(id => this.snapshot!.nodes.find(n => n.id === id && eligible(n, this.policy.active, false)));
    if (nodes.some(n => !n)) throw new AppError('NO_COMPATIBLE_NODES');
    this.lastProbeBatch = performance.now(); const budget = new Budget(20000); this.probeBudget = budget;
    const session = this.session?.generation, policy = this.policy.generation; let cursor = 0;
    const current = (node: Snapshot['nodes'][number]) => !budget.signal.aborted && session === this.session?.generation && policy === this.policy.generation && !this.gate() && this.snapshot?.nodes.some(n => n.id === node.id && n.connectionFingerprint === node.connectionFingerprint) && eligible(node, this.policy.active, false);
    try {
      await budget.run(signal => Promise.all(Array.from({ length: Math.min(4, nodes.length) }, async () => {
        while (cursor < nodes.length && !signal.aborted) {
          const node = nodes[cursor++]!; if (!current(node)) break;
          this.probeResults.set(node.id, { fingerprint: node.connectionFingerprint, latency: null, state: 'testing' }); this.emit();
          try { const result = await this.deps.probe(node, signal); if (current(node)) this.probeResults.set(node.id, { fingerprint: node.connectionFingerprint, latency: result.latencyMs, state: result.healthy ? 'healthy' : 'timeout' }); }
          catch { if (current(node)) this.probeResults.set(node.id, { fingerprint: node.connectionFingerprint, latency: null, state: 'timeout' }); }
          this.emit();
        }
      })));
    } finally { budget.cancel(); budget.dispose(); this.probeBudget = null; for (const [id, value] of this.probeResults) if (value.state === 'testing') this.probeResults.delete(id); this.emit(); }
  }
  private async connect() {
    const gate = this.gate(); if (gate) throw new AppError(gate); if (this.maintenance(this.clock.now())) throw new AppError('CONTROL_UNAVAILABLE');
    const generation = this.policy.generation, session = this.session?.generation, networkGeneration = this.network.generation;
    if (this.deps.demo) throw new AppError('COMPONENTS_UNAVAILABLE');
    if (!this.network.ready) await this.deps.networkDriver?.ensureReady?.();
    if (!this.network.ready) throw new AppError('COMPONENTS_UNAVAILABLE');
    if (this.closing || this.gate() || networkGeneration !== this.network.generation || generation !== this.policy.generation || session !== this.session?.generation) throw new AppError('CANCELLED');
    const node = await selectNode(this.snapshot!.nodes, this.policy.active, this.preferences.nodeId, this.actualNode, null, this.deps.probe);
    if (this.closing || this.gate() || networkGeneration !== this.network.generation || generation !== this.policy.generation || session !== this.session?.generation) throw new AppError('CANCELLED');
    const candidate = { node, mode: this.preferences.mode, rules: this.deps.resources?.rules ?? { schemaVersion: 2, sections: [] }, authorizedUntil: this.snapshot!.usableUntil };
    await this.network.connect(candidate, () => !this.gate() && generation === this.policy.generation && session === this.session?.generation && eligible(node, this.policy.active, false)); this.actualNode = node.id;
  }
  private link(key: 'website' | 'renew' | 'help') { return this.policy.active?.links[key] ?? this.deps.build.links[key]; }
  // The native updater requires Authenticode/Developer ID signatures; unsigned Windows/macOS builds update from the download page.
  private get manualUpdate() { return this.updateArtifact?.signatureIdentity === 'unsigned' && process.platform !== 'linux'; }
  private async openDownloadPage() {
    const feed = this.deps.build.updateFeedUrls[0]; if (!feed) throw new AppError('CONFIGURATION_REQUIRED');
    await this.deps.openExternal(trustedUrl(`${new URL(feed).origin}/`, this.deps.build.trustedWebOrigins));
  }
  private async checkPolicy() {
    if (this.policyBusy) return; this.policyBusy = true; const budget = new Budget(6000, this.publicAbort.signal);
    try { for (const url of this.deps.build.policyUrls) { try { const response = await this.deps.http.request({ url, maxBytes: 262144 }, budget); requireSuccess(response, 'public'); await this.policy.accept(response.body); void this.deps.resources?.apply(response.body); break; } catch { if (!budget.remaining) break; } } }
    finally { budget.dispose(); this.policyBusy = false; this.emit(); }
  }
  private async checkUpdate() {
    if (this.updateBusy) return; this.updateBusy = true; const budget = new Budget(12000, this.publicAbort.signal);
    try {
      if (!this.deps.build.updateFeedUrls.length) { this.updateStatus = '更新发布源尚未配置'; return; }
      this.updateStatus = '正在检查更新'; this.emit(); let index: ReleaseIndex | null = null;
      for (const url of this.deps.build.updateFeedUrls) {
        try { const response = await this.deps.http.request({ url, maxBytes: 262144 }, budget); requireSuccess(response, 'public'); const verified = verifyRelease(response.body, this.deps.build, this.releaseWatermark, this.clock.now()); await this.deps.releaseStore.save({ envelope: response.body, watermark: verified.watermark }); this.releaseWatermark = verified.watermark; this.releaseEnvelope = response.body; index = verified.index; break; } catch { if (!budget.remaining) break; }
      }
      this.updateStatus = index ? '更新索引已验证' : '无法验证更新，请稍后重试';
      if (index) {
        this.releaseIndex = index;
        this.updateArtifact = selectUpdate(index, { platform: process.platform, arch: process.arch, version: this.deps.version ?? '0.1.0', osCompatible: minimum => this.deps.osCompatible?.(minimum) ?? false });
        await this.deps.download?.select(this.updateArtifact);
        this.updateStatus = !this.updateArtifact ? '当前没有兼容的新版本' : this.manualUpdate ? `发现新版本 ${this.updateArtifact.version}，请从下载页安装` : `发现新版本 ${this.updateArtifact.version}，下载由你决定`;
      }
    } finally { budget.dispose(); this.updateBusy = false; this.emit(); }
  }
  async command(input: Command): Promise<CommandResult> {
    try {
      const parsed = CommandSchema.safeParse(input); if (!parsed.success) throw new AppError('INVALID_INPUT'); const command = parsed.data;
      switch (command.type) {
        case 'state': break;
        case 'login': {
          this.probeBudget?.cancel(); this.probeResults.clear();
          if (this.deps.secure.mode === 'locked') throw new AppError('STORAGE_LOCKED');
          const endpoint = this.pool.candidates(this.policy.active)[0]; if (!endpoint) throw new AppError('CONFIGURATION_REQUIRED');
          this.loginBudget?.cancel(); const generation = ++this.loginGeneration; const budget = new Budget(20000); this.loginBudget = budget;
          try {
            const session = await budget.run(() => this.deps.panel.login(endpoint.id, command.email, command.password, budget));
            if (generation !== this.loginGeneration) throw new AppError('CANCELLED');
            this.sync.cancel(); await this.network.disconnect();
            if (generation !== this.loginGeneration) throw new AppError('CANCELLED');
            this.session = session; this.snapshot = null; this.account = null; this.restrictions.clear(); this.startupAttempted = false;
            await this.persist(); if (generation !== this.loginGeneration) throw new AppError('CANCELLED'); await this.refresh(true);
          } finally { budget.dispose(); if (generation === this.loginGeneration) this.loginBudget = null; } break;
        }
        case 'sync': if (performance.now() - this.lastManual >= 10000) { this.lastManual = performance.now(); await this.refresh(true); } else throw new AppError('RATE_LIMITED'); break;
        case 'connect': await this.connect(); break;
        case 'disconnect': await this.network.disconnect(); this.actualNode = null; this.error = null; break;
        case 'repair': if (!this.deps.networkDriver?.repair) throw new AppError('COMPONENTS_UNAVAILABLE'); await this.network.disconnect().catch(() => {}); await this.deps.networkDriver.repair(); await this.network.disconnect(); this.error = null; break;
        case 'logout': {
          const session = this.session, endpoint = this.account?.sourceEndpointId ?? this.deps.build.apiEndpoints[0]?.id;
          this.loginGeneration++; this.loginBudget?.cancel(); this.probeBudget?.cancel(); this.probeResults.clear(); this.sync.cancel(); this.session = null; this.snapshot = null; this.account = null; this.restrictions.clear(); this.renewalUntil = 0;
          await this.deps.secure.clear(); await this.network.disconnect(); this.syncStatus = 'NeedsLogin'; this.error = null;
          if (session && endpoint && this.deps.panel.logout && !this.deps.demo) { const budget = new Budget(3000); try { await this.deps.panel.logout(endpoint, session, budget); } catch { this.diagnostics.record({ stage: 'lifecycle', code: 'REMOTE_LOGOUT_UNAVAILABLE' }); } finally { budget.cancel(); budget.dispose(); } }
          break;
        }
        case 'preferences': {
          const change = command.preferences;
          if (change.launchAtLogin !== this.preferences.launchAtLogin) await this.deps.launchAtLogin(change.launchAtLogin);
          const changedNetwork = change.mode !== this.preferences.mode || change.nodeId !== this.preferences.nodeId;
          const reconnect = changedNetwork && this.network.desiredConnected; if (reconnect) await this.network.disconnect();
          await this.deps.preferences.save(change); this.preferences = change; if (reconnect) await this.connect(); break;
        }
        case 'check-update': await this.checkUpdate(); break;
        case 'download-update': {
          if (!this.updateArtifact || !this.deps.download) throw new AppError('CONFIGURATION_REQUIRED');
          if (this.manualUpdate) { await this.openDownloadPage(); break; }
          void this.deps.download.start().catch(() => this.fail('UPDATE_DOWNLOAD_FAILED')); break;
        }
        case 'pause-update': await this.deps.download?.pause(); break;
        case 'cancel-update': await this.deps.download?.cancel(); break;
        case 'install-update': {
          if (this.manualUpdate) { await this.openDownloadPage(); break; }
          if (!this.updateArtifact || !this.deps.download || !this.deps.installer?.ready) throw new AppError('COMPONENTS_UNAVAILABLE');
          const selected = this.updateArtifact;
          if (!await this.deps.confirmInstall?.(selected.version)) break;
          // A fresh, current index is required; a failed check cannot authorize installing old cached metadata.
          this.releaseIndex = null; await this.checkUpdate();
          if (!this.releaseIndex || this.updateArtifact?.id !== selected.id) throw new AppError('UPDATE_VERIFY_FAILED');
          await this.network.disconnect(); installationGate(selected, this.releaseIndex, this.clock.now(), this.network.state === 'Disconnected');
          if (!this.releaseEnvelope) throw new AppError('UPDATE_VERIFY_FAILED');
          await this.deps.installer.install(selected, await this.deps.download.verifiedPath(selected), this.releaseEnvelope); break;
        }
        case 'probe-nodes': await this.probeNodes(command.nodeIds); break;
        case 'diagnostics': await this.deps.exportDiagnostics(this.diagnostics.export(this.deps.version ?? '0.1.0', process.platform, process.arch)); break;
        case 'open-link': {
          const link = this.link(command.link); if (!link) throw new AppError('CONFIGURATION_REQUIRED');
          const opened = await this.deps.openExternal(trustedUrl(link, this.deps.build.trustedWebOrigins), command.link === 'renew' ? this.view().account?.email : undefined);
          if (opened && command.link === 'renew') this.renewalUntil = this.clock.now() + 600000; break;
        }
        case 'renewal-return': if (this.renewalUntil > this.clock.now() && performance.now() - this.renewalRefresh >= 30000) { this.renewalRefresh = performance.now(); await this.refresh(true); } break;
      }
      this.emit(); return { ok: true, state: this.view() };
    } catch (e) { const code = errorCode(e); this.fail(code); return { ok: false, state: this.view(), error: code }; }
  }
  networkChanged(refresh = true): Promise<void> {
    if (this.recovery) return this.recovery;
    this.recovery = (async () => {
      const intended = this.network.desiredConnected && this.network.state === 'Connected', session = this.session?.generation;
      await this.network.disconnect(); const generation = this.network.generation;
      if (refresh) await this.refresh(true);
      if (intended && !this.closing && generation === this.network.generation && session === this.session?.generation && !this.gate() && !this.maintenance(this.clock.now())) await this.connect();
    })().catch(error => this.fail(errorCode(error))).finally(() => { this.recovery = null; }); return this.recovery;
  }
  async suspend() { const intent = this.network.desiredConnected && this.network.state === 'Connected'; this.probeBudget?.cancel(); await this.network.disconnect(); this.suspended = { intent, generation: this.network.generation }; await this.persist(); }
  async resume() {
    const saved = this.suspended; this.suspended = null;
    if (this.gate() || this.maintenance(this.clock.now())) await this.network.disconnect(); await this.refresh(true);
    if (saved?.intent && saved.generation === this.network.generation && !this.closing && !this.gate() && !this.maintenance(this.clock.now())) await this.connect();
  }
  async nativeFailure(code: ErrorCode) {
    const intended = this.network.desiredConnected; this.network.externalFailure(code); this.actualNode = null; this.fail(code);
    if (!intended || this.closing || this.recovery) return;
    this.recovery = (async () => { await this.network.disconnect(); await this.deps.networkDriver?.initialize?.(); if (this.network.ready && !this.gate() && !this.closing) await this.connect(); })().catch(e => this.fail(errorCode(e))).finally(() => { this.recovery = null; });
    await this.recovery;
  }
  async stop() { this.closing = true; if (this.timer) clearInterval(this.timer); this.publicAbort.abort(); this.loginGeneration++; this.loginBudget?.cancel(); this.probeBudget?.cancel(); this.sync.cancel(); await this.network.disconnect(); await this.deps.download?.pause(); await this.deps.resources?.stop(); await this.persist(); }
}
