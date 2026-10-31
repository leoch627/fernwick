import { constants } from 'node:fs';
import { mkdir, lstat, open, readFile, rename, rm, statfs } from 'node:fs/promises';
import { join } from 'node:path';
import https from 'node:https';
import { z } from 'zod';
import type { BuildConfig } from '../shared/schema';
import { AppError, assert } from '../shared/errors';
import { trustedUrl } from '../domain/trust';
import { strictJson } from '../domain/json';
import { atomicWrite } from './storage';
import { ArtifactSchema, requiredDiskBytes, verifyArtifact, type Artifact } from './update';

export interface DownloadView { status: 'idle' | 'available' | 'downloading' | 'paused' | 'verifying' | 'ready' | 'failed'; version: string | null; received: number; total: number; error: string | null; }
export interface DownloadResponse { status: number; headers: Record<string, string | undefined>; body: AsyncIterable<Uint8Array>; close(): void; }
export interface DownloadTransport { open(url: string, offset: number, etag: string | null, signal: AbortSignal): Promise<DownloadResponse>; }
export class HttpsDownloadTransport implements DownloadTransport {
  open(raw: string, offset: number, etag: string | null, signal: AbortSignal): Promise<DownloadResponse> {
    return new Promise((resolve, reject) => {
      const request = https.get(raw, { agent: false, signal, headers: { 'user-agent': 'StarRail-Updater/0.1', 'accept-encoding': 'identity', ...(offset ? { range: `bytes=${offset}-`, ...(etag ? { 'if-range': etag } : {}) } : {}) } }, response => {
        const headers: Record<string, string | undefined> = {};
        for (const [name, value] of Object.entries(response.headers)) headers[name] = typeof value === 'string' ? value : undefined;
        // No redirects, cookies, API tokens or system proxy inheritance.
        resolve({ status: response.statusCode ?? 0, headers, body: response, close: () => { response.destroy(); request.destroy(); } });
      });
      request.setTimeout(15000, () => request.destroy(new Error('Download idle timeout')));
      request.once('error', () => reject(new AppError(signal.aborted ? 'CANCELLED' : 'UPDATE_DOWNLOAD_FAILED')));
    });
  }
}
const RecordSchema = z.object({ schemaVersion: z.literal(1), artifact: ArtifactSchema, createdAt: z.number().safe(), etag: z.string().max(512).nullable(), complete: z.boolean() }).strict();
type DownloadRecord = z.infer<typeof RecordSchema>;
const MAX_AGE = 7 * 86400000;

/** A single bounded download slot. Only artifacts from an already verified release index are accepted. */
export class ArtifactDownload {
  private artifact: Artifact | null = null; private record: DownloadRecord | null = null;
  private running: Promise<void> | null = null; private abort: AbortController | null = null;
  private mutations: Promise<void> = Promise.resolve(); private changing = 0; private intent = 0;
  private state: DownloadView = { status: 'idle', version: null, received: 0, total: 0, error: null };
  private stopped = false; private initialized = false;
  constructor(private directory: string, private build: BuildConfig, private transport: DownloadTransport = new HttpsDownloadTransport(), private changed = () => {}, private now = () => Date.now(), private freeBytes = async (path: string) => { const disk = await statfs(path, { bigint: true }); return disk.bavail * disk.bsize; }) {}
  get view(): DownloadView { return { ...this.state }; }
  onChange(listener: () => void) { this.changed = listener; }
  private get partial() { return join(this.directory, 'pending.part'); }
  private get ready() { return join(this.directory, 'pending.bin'); }
  private get metadata() { return join(this.directory, 'pending.json'); }
  private set(change: Partial<DownloadView>) { this.state = { ...this.state, ...change }; this.changed(); }
  private async remove() { await Promise.all([this.partial, this.ready, this.metadata].map(path => rm(path, { force: true }))); this.record = null; }
  private change(operation: () => Promise<void>) {
    this.changing++; const next = this.mutations.then(operation);
    this.mutations = next.catch(() => {}).finally(() => { this.changing--; }); return next;
  }
  async select(input: Artifact | null) {
    const artifact = input ? ArtifactSchema.parse(input) : null;
    if (artifact) trustedUrl(artifact.url, this.build.trustedUpdateOrigins);
    return this.change(() => this.selectSlot(artifact));
  }
  private async selectSlot(artifact: Artifact | null) {
    if (this.initialized && (!this.record || this.now() - this.record.createdAt <= MAX_AGE) && JSON.stringify(this.artifact) === JSON.stringify(artifact)) return;
    this.initialized = true;
    await this.pause(); this.artifact = artifact; this.stopped = false;
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    this.set({ status: artifact ? 'available' : 'idle', version: artifact?.version ?? null, total: artifact?.bytes ?? 0, received: 0, error: null });
    let record: DownloadRecord;
    try { record = RecordSchema.parse(strictJson(await readFile(this.metadata, 'utf8'), 32768)); }
    catch { await this.remove(); return; }
    if (!artifact || JSON.stringify(record.artifact) !== JSON.stringify(artifact) || record.createdAt > this.now() + 120000 || this.now() - record.createdAt > MAX_AGE) { await this.remove(); return; }
    this.record = record;
    try {
      const file = await lstat(record.complete ? this.ready : this.partial);
      assert(file.isFile() && !file.isSymbolicLink() && file.nlink === 1 && file.size <= artifact.bytes);
      if (record.complete) await verifyArtifact(this.ready, artifact);
      this.set({ status: record.complete ? 'ready' : 'paused', received: file.size });
    } catch { await this.remove(); }
  }
  start(): Promise<void> {
    const intent = ++this.intent;
    const begin = (): Promise<void> => {
      if (intent !== this.intent) return Promise.resolve();
      if (this.changing) return this.mutations.then(begin);
      return this.startSlot();
    };
    return begin();
  }
  private startSlot(): Promise<void> {
    if (this.running) return this.running;
    const artifact = this.artifact; if (!artifact) return Promise.reject(new AppError('UPDATE_VERIFY_FAILED'));
    if (this.state.status === 'ready') return Promise.resolve();
    this.stopped = false; this.abort = new AbortController();
    const timeout = setTimeout(() => this.abort?.abort(), 30 * 60 * 1000); timeout.unref();
    this.running = this.transfer(artifact, this.abort.signal).catch(async error => {
      if (error instanceof AppError && error.code === 'UPDATE_VERIFY_FAILED') { await this.remove(); this.set({ received: 0 }); }
      this.set({ status: this.stopped ? 'paused' : 'failed', error: this.stopped ? null : '更新下载或校验失败，可重试' });
    }).finally(() => { clearTimeout(timeout); this.running = null; this.abort = null; }); return this.running;
  }
  private async transfer(artifact: Artifact, signal: AbortSignal) {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    assert(await this.freeBytes(this.directory) >= BigInt(requiredDiskBytes(artifact)), 'UPDATE_DOWNLOAD_FAILED');
    assert(!signal.aborted, 'CANCELLED');
    if (!this.record || this.now() - this.record.createdAt > MAX_AGE) {
      await this.remove(); this.record = { schemaVersion: 1, artifact, createdAt: this.now(), etag: null, complete: false };
    }
    await atomicWrite(this.metadata, JSON.stringify(this.record), () => !signal.aborted);
    let file = await open(this.partial, constants.O_WRONLY | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
    let response: DownloadResponse | null = null;
    try {
      const stat = await file.stat(); assert(stat.isFile() && stat.nlink === 1 && stat.size <= artifact.bytes, 'UPDATE_VERIFY_FAILED');
      let offset = stat.size; this.set({ status: 'downloading', received: offset, error: null });
      if (offset < artifact.bytes) {
        response = await this.transport.open(trustedUrl(artifact.url, this.build.trustedUpdateOrigins), offset, this.record.etag, signal);
        assert(!signal.aborted, 'CANCELLED');
        assert(!response.headers['content-encoding'] || response.headers['content-encoding'] === 'identity', 'UPDATE_DOWNLOAD_FAILED');
        if (response.status === 200) { if (offset) await file.truncate(0); offset = 0; }
        else if (response.status === 206 && offset > 0) {
          const range = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers['content-range'] ?? '');
          assert(range && Number(range[1]) === offset && Number(range[2]) === artifact.bytes - 1 && Number(range[3]) === artifact.bytes, 'UPDATE_DOWNLOAD_FAILED');
        } else throw new AppError('UPDATE_DOWNLOAD_FAILED');
        const length = response.headers['content-length']; if (length !== undefined) assert(/^\d+$/.test(length) && Number(length) === artifact.bytes - offset, 'UPDATE_DOWNLOAD_FAILED');
        const etag = response.headers.etag; this.record.etag = etag && /^"[^"\r\n]{1,500}"$/.test(etag) ? etag : null;
        await atomicWrite(this.metadata, JSON.stringify(this.record));
        for await (const bytes of response.body) {
          assert(!signal.aborted, 'CANCELLED'); assert(offset + bytes.length <= artifact.bytes, 'UPDATE_VERIFY_FAILED');
          let written = 0; while (written < bytes.length) { const result = await file.write(bytes, written, bytes.length - written, offset + written); assert(result.bytesWritten > 0, 'UPDATE_DOWNLOAD_FAILED'); written += result.bytesWritten; }
          offset += bytes.length; this.set({ received: offset });
        }
      }
      assert(!signal.aborted, 'CANCELLED'); assert(offset === artifact.bytes, 'UPDATE_DOWNLOAD_FAILED'); await file.sync();
      this.set({ status: 'verifying' }); await file.close(); file = null as never;
      await verifyArtifact(this.partial, artifact); assert(!signal.aborted, 'CANCELLED');
      await rename(this.partial, this.ready); this.record.complete = true; await atomicWrite(this.metadata, JSON.stringify(this.record));
      this.set({ status: 'ready', received: artifact.bytes, error: null });
    } finally { response?.close(); if (file) await file.close(); }
  }
  async pause() { this.intent++; this.stopped = true; this.abort?.abort(); await this.running; }
  prune() {
    return this.change(async () => {
      if (this.running) { if (this.record && this.now() - this.record.createdAt > MAX_AGE) await this.cancelSlot(); return; }
      try { const record = RecordSchema.parse(strictJson(await readFile(this.metadata, 'utf8'), 32768)); if (record.createdAt > this.now() + 120000 || this.now() - record.createdAt > MAX_AGE) await this.cancelSlot(); }
      catch { await this.remove(); }
    });
  }
  cancel() { return this.change(() => this.cancelSlot()); }
  private async cancelSlot() { await this.pause(); await this.remove(); this.set({ status: this.artifact ? 'available' : 'idle', received: 0, error: null }); }
  async verifiedPath(artifact: Artifact) {
    assert(this.state.status === 'ready' && this.artifact?.id === artifact.id && this.artifact.sha256 === artifact.sha256 && this.record && this.now() - this.record.createdAt <= MAX_AGE, 'UPDATE_VERIFY_FAILED');
    const stat = await lstat(this.ready); assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1, 'UPDATE_VERIFY_FAILED');
    await verifyArtifact(this.ready, artifact); return this.ready;
  }
}
