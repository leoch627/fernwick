import { createHash } from 'node:crypto';
import type { Account, BuildConfig } from '../shared/schema';
import type { ParsedNodes, Session, Snapshot } from './model';
import type { ErrorCode } from '../shared/errors';
export function restriction(a: Account, now: number): ErrorCode | null {
  if (a.sessionStatus === 'invalid') return 'AUTH_INVALID';
  if (a.banned === 'yes') return 'ACCOUNT_BANNED';
  if (a.hasPlan === 'no' || a.serviceAllowed === 'no') return 'NO_SERVICE';
  if (a.expiryKind === 'finite' && Date.parse(a.expiresAt!) <= now) return 'ACCOUNT_EXPIRED';
  if (a.trafficExhausted === 'yes') return 'QUOTA_EXHAUSTED';
  return null;
}
export function createSnapshot(build: BuildConfig, session: Session, account: Account, parsed: ParsedNodes, now: number, age: number, opSeq: number): Snapshot {
  return {
    productId: build.productId, environment: build.environment, adapterId: build.adapterId, accountId: session.accountId,
    sessionGeneration: session.generation, opSeq, account, nodes: parsed.nodes, fullSyncCompletedAt: now,
    usableUntil: Math.min(now + Math.min(age, 604800) * 1000, account.expiresAt ? Date.parse(account.expiresAt) : Infinity),
    maxAgeAtCommitSec: age, quarantinedNodeCount: parsed.quarantined.length, authoritativeEmpty: parsed.authoritativeEmpty,
    contentHash: createHash('sha256').update(JSON.stringify({ account, nodes: parsed.nodes })).digest('hex'),
  };
}
export function tightenSnapshot(snapshot: Snapshot, maxAge: number, account?: Account): Snapshot {
  return { ...snapshot, usableUntil: Math.min(snapshot.usableUntil, snapshot.fullSyncCompletedAt + maxAge * 1000, account?.expiresAt ? Date.parse(account.expiresAt) : Infinity) };
}
export function snapshotGate(input: { build: BuildConfig; session: Session | null; snapshot: Snapshot | null; startupAttempted: boolean; trustedTime: boolean; now: number; restrictions: ReadonlySet<ErrorCode> }): ErrorCode | null {
  const { build, session, snapshot: s, startupAttempted, now, restrictions } = input;
  if (!session || restrictions.has('AUTH_INVALID')) return 'AUTH_INVALID';
  if (!startupAttempted) return 'CONTROL_UNAVAILABLE';
  if (!input.trustedTime) return 'CLOCK_UNTRUSTED';
  if (!s || s.productId !== build.productId || s.environment !== build.environment || s.adapterId !== build.adapterId || s.accountId !== session.accountId || s.sessionGeneration !== session.generation) return 'CONTROL_UNAVAILABLE';
  for (const code of ['ACCOUNT_BANNED', 'NO_SERVICE', 'ACCOUNT_EXPIRED', 'QUOTA_EXHAUSTED', 'NO_AUTHORIZED_NODES'] as const) if (restrictions.has(code)) return code;
  const denied = restriction(s.account, now); if (denied) return denied;
  if (s.account.serviceAllowed !== 'yes') return 'NO_SERVICE';
  if (now >= s.usableUntil) return 'SNAPSHOT_EXPIRED';
  if (!s.nodes.length) return 'NO_AUTHORIZED_NODES';
  if (!s.nodes.some(n => n.compatible && n.tcp && n.udp)) return 'NO_COMPATIBLE_NODES';
  return null;
}
