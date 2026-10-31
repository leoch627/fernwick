import { networkInterfaces } from 'node:os';
import { createHash } from 'node:crypto';
import { tunNames } from '../domain/identity';
/** Address/interface generations only; never sends the address list to UI or diagnostics. */
export class NetworkEvents {
  private previous: string | null = null; private pending: string | null = null; private timer: ReturnType<typeof setInterval> | null = null;
  private pendingSince = 0;
  constructor(private changed: () => Promise<void>, private read = networkInterfaces, private now = () => performance.now()) {}
  sample() {
    const records = Object.entries(this.read()).filter(([name]) => !(Object.values(tunNames) as string[]).includes(name)).flatMap(([name, addresses]) => (addresses ?? []).filter(a => !a.internal).map(a => [name, a.family, a.address, a.netmask, a.scopeid ?? 0].join('|'))).sort();
    const hash = createHash('sha256').update(records.join('\n')).digest('hex');
    if (this.previous === null) { this.previous = hash; return false; }
    if (hash === this.previous) { this.pending = null; return false; }
    if (hash !== this.pending) { this.pending = hash; this.pendingSince = this.now(); return false; }
    if (this.now() - this.pendingSince < 2000) return false;
    this.previous = hash; this.pending = null; return true;
  }
  start() { if (this.timer) return; this.sample(); this.timer = setInterval(() => { if (this.sample()) void this.changed().catch(() => {}); }, 1000); this.timer.unref(); }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }
}
