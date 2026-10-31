import { describe, expect, it } from 'vitest';
import { snapshotGate, tightenSnapshot, restriction, createSnapshot } from '../src/domain/authorization';
import { ConservativeClock } from '../src/domain/time';
import { AccountSchema, RefreshSchema, defaults } from '../src/shared/schema';
import { build, session, account, snapshot, now, parsed } from './fixtures';
const input = (): Parameters<typeof snapshotGate>[0] => ({ build, session, snapshot, startupAttempted: true, trustedTime: true, now, restrictions: new Set() });
describe('authorization and lifetime', () => {
  it('AC-05 requires a startup attempt before using valid cached authorization', () => { expect(snapshotGate({ ...input(), startupAttempted: false })).toBe('CONTROL_UNAVAILABLE'); expect(snapshotGate(input())).toBeNull(); });
  it('AC-06 a narrower policy permanently tightens the existing snapshot', () => { const narrow = tightenSnapshot(snapshot, 3600); expect(tightenSnapshot(narrow, 86400).usableUntil).toBe(now + 3600000); expect(narrow.fullSyncCompletedAt).toBe(now); });
  it('AC-06 account polling cannot renew the full-sync clock', () => { const renewed = { ...account, expiresAt: new Date(now + 90 * 86400000).toISOString() }; expect(tightenSnapshot(snapshot, 86400, renewed).usableUntil).toBe(snapshot.usableUntil); });
  it('AC-07 exact expiry denies connections', () => { expect(snapshotGate({ ...input(), now: snapshot.usableUntil })).toBe('SNAPSHOT_EXPIRED'); expect(restriction({ ...account, expiresAt: new Date(now).toISOString() }, now)).toBe('ACCOUNT_EXPIRED'); });
  it('AC-10 isolates account, environment and restored session', () => { for (const bad of [{ ...snapshot, accountId: 'other' }, { ...snapshot, environment: 'production' }, { ...snapshot, sessionGeneration: 'new-login' }]) expect(snapshotGate({ ...input(), snapshot: bad })).toBe('CONTROL_UNAVAILABLE'); });
  it('AC-30 polling cannot remove a latched restriction', () => { expect(snapshotGate({ ...input(), restrictions: new Set(['ACCOUNT_BANNED' as const]) })).toBe('ACCOUNT_BANNED'); });
  it('AC-67 separates unknown expiry from permission', () => { const unknown = { ...account, expiryKind: 'unknown' as const, expiresAt: null }; const s = createSnapshot(build, session, unknown, parsed, now, 86400, 2); expect(snapshotGate({ ...input(), snapshot: s })).toBeNull(); expect(snapshotGate({ ...input(), snapshot: { ...s, account: { ...unknown, serviceAllowed: 'unknown' } } })).toBe('NO_SERVICE'); });
  it('AC-67 preserves multiple facts and displays restrictions in priority order', () => { expect(restriction({ ...account, banned: 'yes', hasPlan: 'no', trafficExhausted: 'yes', expiresAt: new Date(now - 1).toISOString() }, now)).toBe('ACCOUNT_BANNED'); });
  it('rejects inconsistent expiry and unsafe numeric traffic', () => { expect(() => AccountSchema.parse({ ...account, expiresAt: null })).toThrow(); expect(() => AccountSchema.parse({ ...account, usedBytes: 9007199254740993 })).toThrow(); });
  it('rejects remote intervals that cannot fit in the cache window', () => { expect(() => RefreshSchema.parse({ ...defaults, maxSnapshotAgeSec: 600 })).toThrow(); expect(() => RefreshSchema.parse({ ...defaults, accountIntervalSec: 3000 })).toThrow(); });
});
describe('conservative time', () => {
  it('AC-31 uses monotonic elapsed time and blocks a large rollback', () => { let wall = now, mono = 0; const clock = new ConservativeClock(now, () => wall, () => mono); mono = 60000; wall -= 3600000; expect(clock.now()).toBe(now + 60000); expect(clock.trusted).toBe(false); clock.revalidateAfterOnlineSync(); expect(clock.trusted).toBe(false); });
  it('AC-31 restarting with a rolled-back wall clock cannot reset authorization', () => { const clock = new ConservativeClock(now, () => now - 600000, () => 0); expect(clock.trusted).toBe(false); expect(clock.now()).toBe(now); });
  it('AC-31 a small rollback cannot move the saved upper bound backwards', () => { const clock = new ConservativeClock(now, () => now - 60000, () => 0); expect(clock.now()).toBe(now); expect(clock.trusted).toBe(true); });
});
