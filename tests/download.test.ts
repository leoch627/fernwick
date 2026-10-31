import { afterEach, expect, it, vi } from 'vitest';
import { mkdtemp, rm, readFile, writeFile, symlink, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { ArtifactDownload, type DownloadTransport, type DownloadResponse } from '../src/services/download';
import type { Artifact } from '../src/services/update';
import { build, deferred } from './fixtures';
const body = Buffer.from('signed installer fixture content');
const artifact: Artifact = { id: 'linux-0.2.0', version: '0.2.0', platform: 'linux', arch: 'x64', format: 'deb', minimumOS: '24.04', url: 'https://updates.example.invalid/app.deb', bytes: body.length, sha256: createHash('sha256').update(body).digest('hex'), unpackedBytes: 1024, backupBytes: 1024, coreVersion: '26.10.29', coreSha256: 'a'.repeat(64), helperProtocol: 1, signatureIdentity: 'fixture' };
const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map(path => rm(path, { recursive: true, force: true }))); });
async function setup(transport: DownloadTransport, clock = () => Date.now(), free = 10n ** 12n) {
  const directory = await mkdtemp(join(tmpdir(), 'starrail-download-')); directories.push(directory);
  const download = new ArtifactDownload(directory, { ...build, trustedUpdateOrigins: ['https://updates.example.invalid'] }, transport, () => {}, clock, async () => free);
  await download.select(artifact); return { download, directory };
}
function response(data = body, status = 200, headers: Record<string, string> = {}): DownloadResponse { return { status, headers: { 'content-length': String(data.length), ...headers }, body: (async function* () { yield data; })(), close() {} }; }
it('downloads exactly the signed bytes, verifies them and re-verifies immediately before install', async () => {
  const { download } = await setup({ open: async () => response() }); await download.start(); expect(download.view).toMatchObject({ status: 'ready', received: body.length });
  const path = await download.verifiedPath(artifact); expect(await readFile(path)).toEqual(body);
  await writeFile(path, Buffer.alloc(body.length)); await expect(download.verifiedPath(artifact)).rejects.toThrow();
});
it('pause and restart resume from the actual partial-file offset with a strong If-Range ETag', async () => {
  const partial = deferred<void>(); let calls = 0; const offsets: number[] = [];
  const transport: DownloadTransport = { open: async (_url, offset, etag, signal) => {
    offsets.push(offset); if (++calls > 1) { expect(etag).toBe('"v1"'); return response(body.subarray(offset), 206, { 'content-range': `bytes ${offset}-${body.length - 1}/${body.length}` }); }
    return { status: 200, headers: { etag: '"v1"', 'content-length': String(body.length) }, close() {}, body: (async function* () { yield body.subarray(0, 8); partial.resolve(); await new Promise<void>((_, reject) => { signal.addEventListener('abort', () => reject(new Error('cancelled')), { once: true }); if (signal.aborted) reject(new Error('cancelled')); }); })() };
  } };
  const { download, directory } = await setup(transport); const running = download.start(); await partial.promise; await download.pause(); await running;
  expect(download.view.status).toBe('paused');
  const restarted = new ArtifactDownload(directory, { ...build, trustedUpdateOrigins: ['https://updates.example.invalid'] }, transport, () => {}, () => Date.now(), async () => 10n ** 12n);
  await restarted.select(artifact); expect(restarted.view.received).toBe(8); await restarted.start(); expect(restarted.view.status).toBe('ready'); expect(offsets).toEqual([0, 8]);
});
it('a range request answered with 200 safely restarts the file instead of appending a duplicate', async () => {
  let calls = 0; const { download } = await setup({ open: async () => ++calls === 1 ? { ...response(), body: (async function* () { yield body.subarray(0, 5); throw new Error('reset'); })() } : response() });
  await download.start(); expect(download.view.status).toBe('failed'); await download.start(); expect(download.view.status).toBe('ready'); expect(await readFile(await download.verifiedPath(artifact))).toEqual(body);
});
it.each([302, 404, 500])('never accepts redirects or error pages (%i)', async status => {
  const { download } = await setup({ open: async () => response(body, status, { location: 'https://elsewhere.invalid/' }) }); await download.start(); expect(download.view.status).toBe('failed');
});
it('rejects bad range offsets instead of corrupting or blessing a partial download', async () => {
  let calls = 0; const { download } = await setup({ open: async () => ++calls === 1 ? { ...response(), body: (async function* () { yield body.subarray(0, 8); throw new Error('reset'); })() } : response(body.subarray(8), 206, { 'content-range': `bytes 9-${body.length - 1}/${body.length}` }) });
  await download.start(); await download.start(); expect(download.view.status).toBe('failed');
});
it('wrong hash or oversized data is removed and cannot be installed', async () => {
  for (const data of [Buffer.alloc(body.length), Buffer.concat([body, Buffer.from('x')])]) {
    const { download, directory } = await setup({ open: async () => ({ ...response(data), headers: {} }) }); await download.start();
    expect(download.view.status).toBe('failed'); await expect(lstat(join(directory, 'pending.bin'))).rejects.toThrow(); await expect(download.verifiedPath(artifact)).rejects.toThrow();
  }
});
it('cancellation and release withdrawal remove the pending artifact', async () => {
  const { download, directory } = await setup({ open: async () => response() }); await download.start(); await download.select(null);
  expect(download.view.status).toBe('idle'); await expect(lstat(join(directory, 'pending.bin'))).rejects.toThrow();
});
it('untrusted origins and inadequate disk space fail before a network request', async () => {
  const open = vi.fn(async () => response()); const { download } = await setup({ open }, () => Date.now(), 10n);
  await download.start(); expect(download.view.status).toBe('failed'); expect(open).not.toHaveBeenCalled();
  await expect(download.select({ ...artifact, url: 'https://evil.invalid/' })).rejects.toThrow(); expect(open).not.toHaveBeenCalled();
});
it('old partial files are removed after seven days and cannot be resurrected on restart', async () => {
  let now = Date.now(); const { download, directory } = await setup({ open: async () => response() }, () => now); await download.start(); now += 7 * 86400000 + 1;
  await download.prune(); await expect(lstat(join(directory, 'pending.bin'))).rejects.toThrow(); expect(download.view.received).toBe(0);
});
it('a symlink in the download slot cannot overwrite another file', async () => {
  const { download, directory } = await setup({ open: async () => response() }); const external = join(directory, 'other'); await writeFile(external, 'keep');
  // A resume record makes transfer preserve the slot, so O_NOFOLLOW must reject it.
  await writeFile(join(directory, 'pending.json'), JSON.stringify({ schemaVersion: 1, artifact, createdAt: Date.now(), etag: null, complete: false }));
  const fresh = new ArtifactDownload(directory, { ...build, trustedUpdateOrigins: ['https://updates.example.invalid'] }, { open: async () => response() });
  await writeFile(join(directory, 'pending.part'), body.subarray(0, 2)); await fresh.select(artifact); await rm(join(directory, 'pending.part')); await symlink(external, join(directory, 'pending.part')); await fresh.start();
  expect(await readFile(external, 'utf8')).toBe('keep'); expect(fresh.view.status).toBe('failed'); await download.pause();
});
it('a pause supersedes a download queued behind a changing release selection', async () => {
  const open = vi.fn(async () => response()); const { download } = await setup({ open });
  const selection = download.select({ ...artifact, id: 'replacement', version: '0.3.0' });
  const queued = download.start(); await download.pause(); await Promise.all([selection, queued]);
  expect(open).not.toHaveBeenCalled(); expect(download.view).toMatchObject({ status: 'available', version: '0.3.0' });
});
it('withdrawal during a pending disk check cannot start the network or retain a download', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'starrail-download-race-')); directories.push(directory);
  const space = deferred<bigint>(), entered = deferred<void>(); const open = vi.fn(async () => response());
  const download = new ArtifactDownload(directory, { ...build, trustedUpdateOrigins: ['https://updates.example.invalid'] }, { open }, () => {}, () => Date.now(), async () => { entered.resolve(); return space.promise; });
  await download.select(artifact); const running = download.start(); await entered.promise;
  const withdrawn = download.select(null); const paused = download.pause();
  space.resolve(10n ** 12n); await Promise.all([running, withdrawn, paused]); expect(open).not.toHaveBeenCalled(); expect(download.view.status).toBe('idle');
});
