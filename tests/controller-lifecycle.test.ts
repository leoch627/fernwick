import { afterEach, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ClientController, type ControllerDeps } from '../src/main/controller';
import { DemoPanel } from '../src/main/demo';
import { JsonStore, SecureStore } from '../src/services/storage';
import { PersistedSchema } from '../src/domain/persisted';
import { PreferencesSchema } from '../src/shared/schema';
import { parseSubscription } from '../src/domain/subscription';
import type { NetworkDriver } from '../src/platform/network';
import type { Session } from '../src/domain/model';
import { build, options, deferred } from './fixtures';
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()!(); });
class LifecyclePanel extends DemoPanel {
  wait: Promise<void> | null = null; expired = false; reads = 0; onRead = () => {};
  async fetchAccount(endpoint: string, session: Session) {
    this.reads++; this.onRead(); if (this.wait) await this.wait;
    const value = await super.fetchAccount(endpoint, session);
    return this.expired ? { ...value, expiresAt: new Date(Date.now() - 10000).toISOString(), serviceAllowed: 'no' as const } : value;
  }
}
async function client(extra: Partial<ControllerDeps> = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'starrail-lifecycle-')); const panel = new LifecyclePanel();
  const driver: NetworkDriver = { verified: true, prepare: vi.fn(async () => 'fixture-only'), protect: vi.fn(async () => {}), start: vi.fn(async () => {}), probe: vi.fn(async () => ({ tcp: true, dns: true, udp: true, ipv6: true })), commit: vi.fn(async () => {}), cleanup: vi.fn(async () => {}) };
  const controller = new ClientController({
    build, panel, demo: false, networkDriver: driver, probe: async () => ({ healthy: true, latencyMs: 1 }),
    secure: new SecureStore(join(directory, 'secret'), { available: () => false, encrypt: () => { throw new Error(); }, decrypt: () => { throw new Error(); } }, raw => PersistedSchema.parse(raw)),
    preferences: new JsonStore(join(directory, 'preferences'), raw => PreferencesSchema.parse(raw)),
    policyStore: new JsonStore(join(directory, 'policy'), raw => raw as never), releaseStore: new JsonStore(join(directory, 'release'), raw => raw as never),
    parse: async raw => parseSubscription(raw, options), http: { request: async () => { throw new Error('No live service in tests'); } },
    openExternal: async () => false, exportDiagnostics: async () => {}, launchAtLogin: async () => {}, ...extra,
  });
  cleanups.push(async () => { await controller.stop(); await rm(directory, { recursive: true, force: true }); });
  await controller.start(); expect((await controller.command({ type: 'login', email: 'test@example.invalid', password: 'fixture-only' })).ok).toBe(true);
  expect((await controller.command({ type: 'connect' })).ok).toBe(true); expect(controller.view().connection).toBe('Connected');
  return { controller, panel, driver };
}
it('network change bursts coalesce into one refresh and one controlled reconnect', async () => {
  const { controller, panel, driver } = await client(); const reads = panel.reads;
  await Promise.all([controller.networkChanged(), controller.networkChanged(), controller.networkChanged()]);
  expect(panel.reads).toBe(reads + 1); expect(driver.start).toHaveBeenCalledTimes(2); expect(controller.view().connection).toBe('Connected');
});
it('a manual disconnect during recovery refresh prevents a late reconnect', async () => {
  const { controller, panel, driver } = await client(); const pending = deferred<void>(), read = deferred<void>(); panel.wait = pending.promise; panel.onRead = read.resolve;
  const recovery = controller.networkChanged(); await read.promise; await controller.command({ type: 'disconnect' }); pending.resolve(); await recovery;
  expect(driver.start).toHaveBeenCalledTimes(1); expect(controller.view().connection).toBe('Disconnected');
});
it('suspend cleans up immediately and resume restores prior intent only once', async () => {
  const { controller, driver } = await client(); await controller.suspend(); expect(controller.view().connection).toBe('Disconnected');
  await controller.resume(); await controller.resume(); expect(driver.start).toHaveBeenCalledTimes(2); expect(controller.view().connection).toBe('Connected');
});
it('a user disconnect or logout while suspended cannot be undone by resume', async () => {
  for (const type of ['disconnect', 'logout'] as const) {
    const { controller, driver } = await client(); await controller.suspend(); await controller.command({ type }); await controller.resume();
    expect(driver.start).toHaveBeenCalledTimes(1); expect(controller.view().connection).toBe('Disconnected');
  }
});
it('renewed account restrictions on wake forbid reconnecting a previously healthy session', async () => {
  const { controller, panel, driver } = await client(); await controller.suspend(); panel.expired = true; await controller.resume();
  expect(driver.start).toHaveBeenCalledTimes(1); expect(controller.view().connection).toBe('Disconnected'); expect(controller.view().error).not.toBe(null);
});
it('shutdown cleans the network before awaiting unrelated update download work', async () => {
  const paused = deferred<void>(); let didPause = false;
  const { controller, driver } = await client({ download: { onChange() {}, prune: async () => {}, pause: async () => { didPause = true; await paused.promise; }, view: { status: 'idle', version: null, received: 0, total: 0, error: null } } as unknown as ControllerDeps['download'] });
  const before = vi.mocked(driver.cleanup).mock.calls.length; const stopping = controller.stop(); await vi.waitFor(() => expect(didPause).toBe(true));
  expect(driver.cleanup).toHaveBeenCalledTimes(before + 1); expect(controller.view().connection).toBe('Disconnected'); paused.resolve(); await stopping;
});
