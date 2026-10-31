import { AppError } from '../shared/errors';
export class Budget {
  readonly controller = new AbortController(); readonly started = performance.now();
  private readonly timer: ReturnType<typeof setTimeout>;
  constructor(readonly durationMs: number, parent?: AbortSignal) {
    this.timer = setTimeout(() => this.controller.abort(), durationMs); this.timer.unref?.();
    parent?.addEventListener('abort', this.cancel, { once: true });
    if (parent?.aborted) this.cancel();
    this.parent = parent;
  }
  private parent?: AbortSignal;
  get signal() { return this.controller.signal; }
  get remaining() { return Math.max(0, this.durationMs - (performance.now() - this.started)); }
  check() { if (this.signal.aborted || !this.remaining) throw new AppError('CANCELLED'); }
  cancel = () => this.controller.abort();
  dispose() { clearTimeout(this.timer); this.parent?.removeEventListener('abort', this.cancel); }
  async run<T>(fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.check(); let abort: () => void = () => {};
    try { return await Promise.race([fn(this.signal), new Promise<never>((_, reject) => { abort = () => reject(new AppError('CANCELLED')); this.signal.addEventListener('abort', abort, { once: true }); if (this.signal.aborted) abort(); })]); }
    finally { this.signal.removeEventListener('abort', abort); }
  }
}
export class ConservativeClock {
  private anchorWall: number; private anchorMono: number; private upper: number;
  trusted = true;
  constructor(savedUpper = 0, private wall = () => Date.now(), private mono = () => performance.now()) {
    this.anchorWall = wall(); this.anchorMono = mono(); this.upper = Math.max(savedUpper, this.anchorWall);
    if (this.anchorWall < savedUpper - 120000) this.trusted = false;
  }
  now() {
    const wall = this.wall(), monotonic = this.anchorWall + Math.max(0, this.mono() - this.anchorMono);
    if (wall < this.upper - 120000 || wall < monotonic - 120000) this.trusted = false;
    this.upper = Math.floor(Math.max(this.upper, wall, monotonic)); return this.upper;
  }
  get highWater() { return this.now(); }
  revalidateAfterOnlineSync() {
    // Without an authoritative server clock, a still-rolled-back local clock is never trusted.
    if (this.wall() < this.upper - 120000) return;
    this.anchorWall = Math.max(this.wall(), this.upper); this.anchorMono = this.mono(); this.trusted = true;
  }
}
export const jitter = (seconds: number, random = Math.random) => seconds * 1000 * (0.9 + random() * 0.2);
