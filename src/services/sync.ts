import type { Account, BuildConfig, Policy } from '../shared/schema';
import type { ParsedNodes, Session, Snapshot, SubscriptionDescriptor } from '../domain/model';
import { createSnapshot, restriction, tightenSnapshot } from '../domain/authorization';
import { AppError, errorCode, type ErrorCode } from '../shared/errors';
import { Budget } from '../domain/time';
import type { PanelAdapter } from './panel';
import { EndpointPool } from './endpoints';
export interface SyncHooks {
  session(): Session | null; policy(): Policy | null; now(): number; snapshot(): Snapshot | null;
  account(account: Account): void; restrict(code: ErrorCode): void;
  commit(snapshot: Snapshot, signal: AbortSignal): Promise<void>;
  done(error: ErrorCode | null): void;
  parse(raw: string, descriptor: SubscriptionDescriptor, signal: AbortSignal): Promise<ParsedNodes>;
}
/** Single control-plane writer. Account requests coalesce into full sync; a full request upgrades queued polls. */
export class SyncCoordinator {
  private running: Promise<void> | null = null; private current: Budget | null = null;
  private sequence = 0; private pendingFull = false; private activeFull = false;
  private blockedUntil = 0; private failures = 0;
  constructor(private build: BuildConfig, private panel: PanelAdapter, private pool: EndpointPool, private hooks: SyncHooks) {}
  cancel() { this.sequence++; this.current?.cancel(); this.pendingFull = false; }
  request(full = true): Promise<void> {
    if (this.running) { if (full && (!this.activeFull || this.current?.signal.aborted)) this.pendingFull = true; return this.running; }
    this.activeFull = full;
    this.running = (async () => { await this.execute(full); if (this.pendingFull) { this.pendingFull = false; this.activeFull = true; await this.execute(true); } })().finally(() => { this.running = null; this.activeFull = false; });
    return this.running;
  }
  private async execute(full: boolean) {
    const session = this.hooks.session(); if (!session) return;
    const seq = ++this.sequence; const budget = new Budget(20000); this.current = budget;
    let networkFinished = false;
    const fresh = () => { if (!networkFinished) budget.check(); if (budget.signal.aborted || seq !== this.sequence || session.generation !== this.hooks.session()?.generation) throw new AppError('CANCELLED'); };
    let result: ErrorCode | null = null;
    try {
      if (this.hooks.now() < this.blockedUntil) throw new AppError('RATE_LIMITED', this.blockedUntil - this.hooks.now());
      const endpoints = this.pool.candidates(this.hooks.policy()); if (!endpoints.length) throw new AppError(this.build.deploymentVerified ? 'CONTROL_UNAVAILABLE' : 'CONFIGURATION_REQUIRED');
      let complete = false;
      for (const endpoint of endpoints) {
        try {
          fresh(); const account = await budget.run(() => this.panel.fetchAccount(endpoint.id, session, budget)); fresh();
          if (account.accountId !== session.accountId) throw new AppError('CONTROL_UNAVAILABLE');
          this.hooks.account(account);
          const denial = restriction(account, this.hooks.now());
          if (denial) { this.hooks.restrict(denial); throw new AppError(denial); }
          if (!full) { this.pool.success(endpoint.id); complete = true; break; }
          let descriptor = await budget.run(() => this.panel.fetchSubscriptionDescriptor(endpoint.id, session, budget)); fresh();
          let raw: string;
          try { raw = await budget.run(() => this.panel.fetchNodes(descriptor, budget)); }
          catch (e) {
            if (errorCode(e) !== 'SUBSCRIPTION_CREDENTIAL_INVALID') throw e;
            fresh(); descriptor = await budget.run(() => this.panel.fetchSubscriptionDescriptor(endpoint.id, session, budget)); fresh();
            raw = await budget.run(() => this.panel.fetchNodes(descriptor, budget));
          }
          fresh();
          // Network deadline ends here. Parsing has a separate bounded worker deadline.
          budget.dispose(); networkFinished = true;
          const parsed = await this.hooks.parse(raw, descriptor, budget.signal); fresh();
          if (account.serviceAllowed !== 'yes') throw new AppError('NO_SERVICE');
          const now = this.hooks.now(); const policy = this.hooks.policy(); const age = policy?.refresh.maxSnapshotAgeSec ?? 86400;
          const snapshot = createSnapshot(this.build, session, account, parsed, now, age, seq);
          if (restriction(account, now)) throw new AppError(restriction(account, now)!);
          fresh(); await this.hooks.commit(snapshot, budget.signal); fresh();
          this.pool.success(endpoint.id); complete = true; break;
        } catch (e) {
          fresh();
          const code = errorCode(e); if (code === 'AUTH_INVALID') this.hooks.restrict(code);
          if (!networkFinished && ['CONTROL_UNAVAILABLE', 'SUBSCRIPTION_INVALID'].includes(code)) { this.pool.failure(endpoint.id); result = code; continue; }
          throw e;
        }
      }
      if (!complete) throw new AppError(result ?? 'CONTROL_UNAVAILABLE');
      result = null; this.failures = 0; this.blockedUntil = 0;
    } catch (e) {
      result = errorCode(e);
      if (result === 'CANCELLED' && seq === this.sequence && session.generation === this.hooks.session()?.generation && budget.signal.aborted) result = 'CONTROL_UNAVAILABLE';
      if (result !== 'CANCELLED') { this.failures++; this.blockedUntil = this.hooks.now() + Math.max(e instanceof AppError ? e.retryAfterMs : 0, Math.min(30000 * 2 ** Math.min(this.failures - 1, 4), 300000) * (0.9 + Math.random() * 0.2)); }
    } finally {
      budget.dispose(); this.current = null;
      if (seq === this.sequence && session.generation === this.hooks.session()?.generation) this.hooks.done(result);
    }
  }
}
