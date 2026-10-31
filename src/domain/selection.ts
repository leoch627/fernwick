import type { ProxyNode } from './model';
import type { Policy } from '../shared/schema';
import { Budget } from './time';
import { AppError } from '../shared/errors';
export interface ProbeResult { healthy: boolean; latencyMs: number | null; }
export function eligible(node: ProxyNode, policy: Policy | null, automatic: boolean) {
  const flag = policy?.nodeOperations.find(n => n.nodeId === node.id);
  return node.compatible && node.tcp && node.udp && !flag?.disabledForConnection && (!automatic || flag?.eligibleForAuto !== false);
}
export async function selectNode(nodes: ProxyNode[], policy: Policy | null, manual: string | null, current: string | null, recentHealthy: string | null, probe: (node: ProxyNode, signal: AbortSignal) => Promise<ProbeResult>, signal?: AbortSignal) {
  const candidates = nodes.filter(n => eligible(n, policy, !manual));
  if (manual) { const node = candidates.find(n => n.id === manual); if (!node) throw new AppError('NO_AUTHORIZED_NODES'); const budget = new Budget(6000, signal); try { const result = await budget.run(s => probe(node, s)); if (!result.healthy) throw new AppError('CONNECT_TIMEOUT'); return node; } finally { budget.dispose(); } }
  const recent = candidates.find(n => n.id === (current || recentHealthy));
  const weight = (n: ProxyNode) => n.id === current ? -3 : n.id === recentHealthy ? -2 : recent?.region && recent.region === n.region ? -1 : 0;
  const ordered = [...candidates].sort((a, b) => weight(a) - weight(b) || (policy?.nodeOperations.find(n => n.nodeId === a.id)?.order ?? a.order) - (policy?.nodeOperations.find(n => n.nodeId === b.id)?.order ?? b.order)).slice(0, 3);
  if (!ordered.length) throw new AppError('NO_COMPATIBLE_NODES');
  const budget = new Budget(6000, signal);
  try {
    // Batches cap concurrency at two; the lower-ranked candidate cannot preempt a healthy current node.
    for (let i = 0; i < ordered.length; i += 2) {
      const batch = ordered.slice(i, i + 2); const results = await budget.run(s => Promise.all(batch.map(n => probe(n, s).catch(() => ({ healthy: false, latencyMs: null })))));
      const winner = batch.find((_, j) => results[j]?.healthy); if (winner) return winner;
    }
    throw new AppError('CONNECT_TIMEOUT');
  } finally { budget.cancel(); budget.dispose(); }
}
