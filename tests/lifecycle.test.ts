import { expect, it } from 'vitest';
import type { NetworkInterfaceInfo } from 'node:os';
import { ExpiryReminders, type ReminderState } from '../src/services/reminders';
import { NetworkEvents } from '../src/platform/network-events';
import { osVersionAtLeast } from '../src/services/update';
import { account, now } from './fixtures';
it('expiry reminders cross each threshold once, including after restart and equivalent timezone strings', async () => {
  let saved: ReminderState | null = null; let notices = 0;
  const reminder = new ExpiryReminders('tenant', async value => { saved = value; }, async () => { notices++; });
  await Promise.all([reminder.check(account, [7, 3], now), reminder.check(account, [7, 3], now)]); expect(notices).toBe(1);
  const restarted = new ExpiryReminders('tenant', async value => { saved = value; }, async () => { notices++; }); restarted.restore(saved);
  await restarted.check({ ...account, expiresAt: account.expiresAt!.replace('Z', '+00:00') }, [7, 3], now); expect(notices).toBe(1);
  await restarted.check(account, [7, 3], now + 3 * 86400000); expect(notices).toBe(2);
  await restarted.check(account, [7, 3], Date.parse(account.expiresAt!)); await restarted.check(account, [7, 3], Date.parse(account.expiresAt!) + 1000); expect(notices).toBe(3);
  expect(JSON.stringify(saved)).not.toContain(account.accountId);
});
it('an expiry extension is a new event; unknown/unlimited/banned accounts are not notified', async () => {
  let notices = 0; const reminder = new ExpiryReminders('t', async () => {}, async () => { notices++; });
  await reminder.check(account, [7, 3], now); await reminder.check({ ...account, expiresAt: new Date(now + 6 * 86400000).toISOString() }, [7, 3], now); expect(notices).toBe(2);
  for (const value of [{ ...account, expiryKind: 'unlimited' as const, expiresAt: null }, { ...account, banned: 'yes' as const }, { ...account, sessionStatus: 'invalid' as const }]) await reminder.check(value, [7, 3], now); expect(notices).toBe(2);
});
it('a failed ledger save or a superseded session cannot display a notification', async () => {
  let notices = 0; const reminder = new ExpiryReminders('t', async () => { throw new Error('disk'); }, async () => { notices++; });
  await expect(reminder.check(account, [7, 3], now)).rejects.toThrow(); expect(notices).toBe(0);
  await reminder.check(account, [7, 3], now, () => false); expect(notices).toBe(0);
});
it('network address changes debounce for two seconds and ignore address ordering and the owned TUN', () => {
  const record = (address: string) => ({ address, family: 'IPv4', internal: false, netmask: '255.255.255.0', mac: '00:00:00:00:00:00', cidr: address + '/24' }) as NetworkInterfaceInfo;
  let clock = 0; let interfaces: Record<string, NetworkInterfaceInfo[]> = { eth0: [record('192.0.2.1'), record('192.0.2.2')] };
  const monitor = new NetworkEvents(async () => {}, () => interfaces, () => clock);
  expect(monitor.sample()).toBe(false); interfaces.eth0!.reverse(); expect(monitor.sample()).toBe(false);
  interfaces.starr0 = [record('172.19.0.1')]; expect(monitor.sample()).toBe(false);
  interfaces = { eth0: [record('192.0.2.3')] }; expect(monitor.sample()).toBe(false); clock = 1000; expect(monitor.sample()).toBe(false); clock = 2000; expect(monitor.sample()).toBe(true); expect(monitor.sample()).toBe(false);
});
it('OS compatibility uses numeric components and fails closed for unknown versions', () => {
  expect(osVersionAtLeast('24.04', '24.4')).toBe(true); expect(osVersionAtLeast('10.0.22631', '10.0.22000')).toBe(true);
  expect(osVersionAtLeast('14.9', '14.10')).toBe(false); expect(osVersionAtLeast('unknown', '14')).toBe(false);
});
