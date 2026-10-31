import { afterEach, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ClientController } from '../src/main/controller';
import { DemoPanel } from '../src/main/demo';
import { JsonStore, SecureStore } from '../src/services/storage';
import { PersistedSchema } from '../src/domain/persisted';
import { PreferencesSchema } from '../src/shared/schema';
import type { ArtifactDownload } from '../src/services/download';
import { build, envelope } from './fixtures';

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => { while (cleanup.length) await cleanup.pop()!(); vi.restoreAllMocks(); });
const origin = 'https://updates.mooncloud.net';

async function client(platform: NodeJS.Platform, signatureIdentity: string) {
  vi.spyOn(process, 'platform', 'get').mockReturnValue(platform);
  vi.spyOn(process, 'arch', 'get').mockReturnValue('x64');
  const target = platform === 'win32' ? { platform: 'win32', format: 'nsis', minimumOS: '10.0' } : { platform: 'linux', format: 'deb', minimumOS: '24.04' };
  const now = Date.now();
  const index = envelope({
    schemaVersion: 1, productId: build.productId, environment: build.environment, channel: build.channel,
    issuedAt: new Date(now - 60000).toISOString(), expiresAt: new Date(now + 3600000).toISOString(), releaseSequence: 1, withdrawnIds: [],
    artifacts: [{ id: `${target.platform}-x64-${target.format}-9.0.0`, version: '9.0.0', arch: 'x64', ...target, url: `${origin}/files/releases/9.0.0/app`, bytes: 10, sha256: 'a'.repeat(64), unpackedBytes: 10, backupBytes: 10, coreVersion: '26.10.31', coreSha256: 'b'.repeat(64), helperProtocol: 1, signatureIdentity }],
  }, 'v2board-client-release-v1', 'r1');
  const opened: string[] = [];
  const download = { onChange() {}, prune: async () => {}, pause: async () => {}, select: vi.fn(async () => {}), start: vi.fn(async () => {}), view: { status: 'available', version: '9.0.0', received: 0, total: 10, error: null } };
  const directory = await mkdtemp(join(tmpdir(), 'manual-update-'));
  const controller = new ClientController({
    build: { ...build, updateFeedUrls: [`${origin}/v1/release`], trustedUpdateOrigins: [origin], trustedWebOrigins: [...build.trustedWebOrigins, origin] },
    panel: new DemoPanel(), demo: false, probe: async () => ({ healthy: false, latencyMs: null }),
    secure: new SecureStore(join(directory, 'secret'), { available: () => false, encrypt: () => { throw new Error(); }, decrypt: () => { throw new Error(); } }, raw => PersistedSchema.parse(raw)),
    preferences: new JsonStore(join(directory, 'preferences'), raw => PreferencesSchema.parse(raw)),
    policyStore: new JsonStore(join(directory, 'policy'), raw => raw as never), releaseStore: new JsonStore(join(directory, 'release'), raw => raw as never),
    parse: async () => { throw new Error('unused'); },
    http: { request: async ({ url }) => url.endsWith('/v1/release') ? { status: 200, headers: {}, body: index } : { status: 404, headers: {}, body: '' } },
    openExternal: async url => { opened.push(url); return true; }, exportDiagnostics: async () => {}, launchAtLogin: async () => {},
    download: download as unknown as ArtifactDownload, osCompatible: () => true, version: '1.0.0',
  });
  cleanup.push(async () => { await controller.stop(); await rm(directory, { recursive: true, force: true }); });
  await controller.command({ type: 'check-update' });
  return { controller, opened, download };
}

it('sends unsigned Windows/macOS updates to the download page instead of the native installer', async () => {
  const { controller, opened, download } = await client('win32', 'unsigned');
  expect(controller.view()).toMatchObject({ manualUpdate: true, update: '发现新版本 9.0.0，请从下载页安装' });
  expect((await controller.command({ type: 'download-update' })).ok).toBe(true);
  expect((await controller.command({ type: 'install-update' })).ok).toBe(true);
  expect(opened).toEqual([`${origin}/`, `${origin}/`]);
  expect(download.start).not.toHaveBeenCalled();
});

it('keeps in-app updates for Linux and signed builds', async () => {
  for (const [platform, identity] of [['linux', 'unsigned'], ['win32', 'CN=Moon Cloud Ltd']] as const) {
    const { controller, opened, download } = await client(platform, identity);
    expect(controller.view().manualUpdate).toBe(false);
    await controller.command({ type: 'download-update' });
    expect(download.start).toHaveBeenCalledOnce();
    expect(opened).toEqual([]);
    await cleanup.pop()!();
  }
});
