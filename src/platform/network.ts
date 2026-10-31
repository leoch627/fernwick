import { Budget } from '../domain/time';
import { AppError, errorCode, type ErrorCode } from '../shared/errors';
export type ConnectionState = 'Disconnected' | 'Preparing' | 'Connecting' | 'Connected' | 'Switching' | 'Reconnecting' | 'Disconnecting' | 'RecoveryRequired';
export interface NetworkDriver {
  readonly verified: boolean;
  initialize?(): Promise<void>;
  ensureReady?(): Promise<void>;
  repair?(): Promise<void>;
  setAuthorizedUntil?(deadline: number): void;
  /** Prepare validates immutable input and acquires owner; no global network change before transaction. */
  prepare(candidate: unknown, signal: AbortSignal): Promise<string>;
  protect(ticket: string, deadline: number, signal: AbortSignal): Promise<void>;
  start(ticket: string, signal: AbortSignal): Promise<void>;
  probe(ticket: string, signal: AbortSignal): Promise<{ tcp: boolean; udp: boolean; dns: boolean; ipv6: boolean }>;
  commit(ticket: string, signal: AbortSignal): Promise<void>;
  cleanup(signal: AbortSignal): Promise<void>;
}
/** No mock success: unsupported/missing helpers never touch the host network. */
export class UnavailableDriver implements NetworkDriver {
  readonly verified = false;
  async prepare(): Promise<string> { throw new AppError('COMPONENTS_UNAVAILABLE'); }
  async protect(): Promise<void> { throw new AppError('COMPONENTS_UNAVAILABLE'); }
  async start(): Promise<void> { throw new AppError('COMPONENTS_UNAVAILABLE'); }
  async probe(): Promise<never> { throw new AppError('COMPONENTS_UNAVAILABLE'); }
  async commit(): Promise<void> { throw new AppError('COMPONENTS_UNAVAILABLE'); }
  async cleanup() { /* This driver cannot own any network resources. */ }
}
export class NetworkController {
  state: ConnectionState = 'Disconnected'; desiredConnected = false; generation = 0; lastError: ErrorCode | null = null;
  private running: Promise<void> | null = null; private abort: AbortController | null = null;
  private stopping: Promise<void> | null = null;
  constructor(private driver: NetworkDriver, private changed: () => void = () => {}) {}
  get ready() { return this.driver.verified; }
  private set(state: ConnectionState) { this.state = state; this.changed(); }
  connect(candidate: unknown, gate: () => boolean): Promise<void> {
    if (this.running) return this.running;
    if (!this.driver.verified) { this.lastError = 'COMPONENTS_UNAVAILABLE'; this.changed(); return Promise.reject(new AppError('COMPONENTS_UNAVAILABLE')); }
    this.desiredConnected = true; const generation = ++this.generation; this.abort = new AbortController();
    const valid = () => { if (!this.desiredConnected || generation !== this.generation || !gate()) throw new AppError('CANCELLED'); };
    this.running = (async () => {
      let touched = false; let prepared = false; let transaction: Budget | null = null;
      try {
        this.set('Preparing'); valid();
        const preparation = new Budget(10000, this.abort!.signal); let ticket: string;
        try { prepared = true; ticket = await preparation.run(signal => this.driver.prepare(candidate, signal)); } finally { preparation.dispose(); }
        valid(); this.set('Connecting'); transaction = new Budget(15000); touched = true;
        const attempt = new Budget(12000, this.abort!.signal);
        try {
          await attempt.run(async signal => {
            await this.driver.protect(ticket, performance.now() + transaction!.remaining, signal); valid();
            await this.driver.start(ticket, signal); valid();
            const proof = await this.driver.probe(ticket, signal); valid();
            if (!proof.tcp || !proof.udp || !proof.dns || !proof.ipv6) throw new AppError('CONNECT_TIMEOUT');
            await this.driver.commit(ticket, signal); valid();
          });
        } finally { attempt.dispose(); }
        valid(); this.lastError = null; this.set('Connected');
      } catch (e) {
        this.lastError = errorCode(e) === 'CANCELLED' && this.desiredConnected && generation === this.generation ? 'CONNECT_TIMEOUT' : errorCode(e); this.desiredConnected = false;
        if (touched || prepared) {
          this.set('Disconnecting'); const cleanup = new Budget(Math.min(3000, transaction?.remaining ?? 3000));
          try { await cleanup.run(signal => this.driver.cleanup(signal)); this.set('Disconnected'); }
          catch { this.lastError = 'NETWORK_RECOVERY_REQUIRED'; this.set('RecoveryRequired'); }
          finally { cleanup.dispose(); }
        } else this.set('Disconnected');
        throw new AppError(this.lastError ?? 'CONNECT_TIMEOUT');
      } finally { transaction?.dispose(); }
    })().finally(() => { this.running = null; this.abort = null; }); return this.running;
  }
  disconnect(): Promise<void> {
    if (this.stopping) return this.stopping;
    this.desiredConnected = false; this.generation++; this.abort?.abort();
    this.stopping = (async () => {
      if (this.running) { await this.running.catch(() => {}); if (this.state === 'RecoveryRequired') throw new AppError('NETWORK_RECOVERY_REQUIRED'); return; }
      this.set('Disconnecting'); const cleanup = new Budget(5000);
      try { await cleanup.run(signal => this.driver.cleanup(signal)); this.lastError = null; this.set('Disconnected'); }
      catch { this.lastError = 'NETWORK_RECOVERY_REQUIRED'; this.set('RecoveryRequired'); throw new AppError('NETWORK_RECOVERY_REQUIRED'); }
      finally { cleanup.dispose(); }
    })().finally(() => { this.stopping = null; }); return this.stopping;
  }
  externalFailure(code: ErrorCode) { this.desiredConnected = false; this.generation++; this.abort?.abort(); this.lastError = code; this.set(code === 'NETWORK_RECOVERY_REQUIRED' ? 'RecoveryRequired' : 'Disconnected'); }
}
