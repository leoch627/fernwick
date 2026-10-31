import { afterEach, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ClientController, type ControllerDeps } from '../src/main/controller';
import { DemoPanel } from '../src/main/demo';
import { JsonStore, SecureStore } from '../src/services/storage';
import { PersistedSchema } from '../src/domain/persisted';
import { parseSubscription } from '../src/domain/subscription';
import { PreferencesSchema } from '../src/shared/schema';
import { build, options, uri, deferred } from './fixtures';
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => { while (cleanup.length) await cleanup.pop()!(); });
class TestPanel extends DemoPanel {
  async fetchNodes() { return Array.from({ length: 12 }, (_, i) => uri.replace('node.example.invalid', `node${i}.example.invalid`)).join('\n'); }
}
async function client(probe: ControllerDeps['probe'], demo = false) {
  const directory = await mkdtemp(join(tmpdir(), 'starrail-controller-'));
  const controller = new ClientController({
    build: { ...build, healthTargets: [{ url: 'https://one.invalid/health', status: 204, bodySha256: '0'.repeat(64), failureDomain: 'one' }, { url: 'https://two.invalid/health', status: 204, bodySha256: '0'.repeat(64), failureDomain: 'two' }] },
    panel: new TestPanel(), demo, probe,
    secure: new SecureStore(join(directory, 'secret'), { available: () => false, encrypt: () => { throw new Error(); }, decrypt: () => { throw new Error(); } }, raw => PersistedSchema.parse(raw)),
    preferences: new JsonStore(join(directory, 'preferences'), raw => PreferencesSchema.parse(raw)),
    policyStore: new JsonStore(join(directory, 'policy'), raw => raw as never), releaseStore: new JsonStore(join(directory, 'release'), raw => raw as never),
    parse: async raw => parseSubscription(raw, options), http: { request: async () => { throw new Error('No network in controller tests'); } },
    openExternal: async () => false, exportDiagnostics: async () => {}, launchAtLogin: async () => {},
  });
  cleanup.push(async () => { await controller.stop(); await rm(directory, { recursive: true, force: true }); });
  await controller.start();
  const login = await controller.command({ type: 'login', email: 'test@example.invalid', password: 'fixture-only' });
  expect(login.ok).toBe(true); expect(login.state.nodes).toHaveLength(12); return controller;
}
it('manual probes cap a batch at ten, concurrency at four, and enforce a 30 second cooldown', async () => {
  let active = 0, peak = 0, calls = 0;
  const controller = await client(async () => { active++; calls++; peak = Math.max(peak, active); await new Promise(r => setTimeout(r, 5)); active--; return { healthy: true, latencyMs: 23 }; });
  const nodeIds = controller.view().nodes.slice(0, 10).map(n => n.id);
  const result = await controller.command({ type: 'probe-nodes', nodeIds }); expect(result.ok).toBe(true); expect(peak).toBe(4); expect(calls).toBe(10);
  expect(result.state.nodes.filter(n => n.probe === 'healthy')).toHaveLength(10); expect(result.state.nodes[0]?.latency).toBe(23);
  expect((await controller.command({ type: 'probe-nodes', nodeIds })).error).toBe('RATE_LIMITED');
});
it('rejects oversized or unknown node batches without calling the executor', async () => {
  let calls = 0; const controller = await client(async () => { calls++; return { healthy: true, latencyMs: 1 }; });
  expect((await controller.command({ type: 'probe-nodes', nodeIds: controller.view().nodes.map(n => n.id) })).error).toBe('INVALID_INPUT');
  expect((await controller.command({ type: 'probe-nodes', nodeIds: ['unknown'] })).error).toBe('NO_COMPATIBLE_NODES'); expect(calls).toBe(0);
});
it('logout cancels a running batch and rejects its late latency results', async () => {
  const pending = deferred<{ healthy: boolean; latencyMs: number }>(); let started = false;
  const controller = await client(async () => { started = true; return pending.promise; });
  const running = controller.command({ type: 'probe-nodes', nodeIds: [controller.view().nodes[0]!.id] });
  expect(started).toBe(true); await controller.command({ type: 'logout' }); pending.resolve({ healthy: true, latencyMs: 1 }); await running;
  expect(controller.view().nodes).toEqual([]); expect(controller.view().loggedIn).toBe(false);
});
it('explicit demo does not fake a latency or launch a core', async () => {
  let calls = 0; const controller = await client(async () => { calls++; return { healthy: true, latencyMs: 1 }; }, true);
  expect((await controller.command({ type: 'probe-nodes', nodeIds: [controller.view().nodes[0]!.id] })).error).toBe('COMPONENTS_UNAVAILABLE'); expect(calls).toBe(0);
});
it('failed real probes are displayed as failed, with no latency', async () => {
  const controller = await client(async () => ({ healthy: false, latencyMs: null }));
  const result = await controller.command({ type: 'probe-nodes', nodeIds: [controller.view().nodes[0]!.id] });
  expect(result.state.nodes[0]).toMatchObject({ probe: 'timeout', latency: null });
});
