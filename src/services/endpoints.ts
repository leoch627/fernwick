import type { BuildConfig, Policy } from '../shared/schema';
export class EndpointPool {
  private health = new Map<string, { failures: number; blockedUntil: number; opens: number }>();
  private sticky: { id: string; until: number } | null = null;
  constructor(private endpoints: BuildConfig['apiEndpoints'], private now = () => Date.now()) {}
  candidates(policy: Policy | null) {
    const ids = policy?.endpoints.orderedIds ?? [...this.endpoints].sort((a, b) => a.priority - b.priority).map(e => e.id);
    let list = ids.flatMap(id => { const e = this.endpoints.find(e => e.id === id); return e && !policy?.endpoints.temporarilyDisabledIds.includes(id) && (this.health.get(id)?.blockedUntil ?? 0) <= this.now() ? [e] : []; });
    const sticky = this.sticky; if (sticky && sticky.until > this.now()) list = [...list.filter(e => e.id === sticky.id), ...list.filter(e => e.id !== sticky.id)];
    return list;
  }
  success(id: string) { this.health.delete(id); this.sticky = { id, until: this.now() + 600000 }; }
  failure(id: string) {
    const h = this.health.get(id) ?? { failures: 0, blockedUntil: 0, opens: 0 }; h.failures++;
    if (h.failures >= 3) { h.blockedUntil = this.now() + Math.min(60000 * 2 ** h.opens, 300000); h.opens++; h.failures = 0; }
    this.health.set(id, h); if (this.sticky?.id === id) this.sticky = null;
  }
}
