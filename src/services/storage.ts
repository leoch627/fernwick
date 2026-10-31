import { mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { AppError } from '../shared/errors';
import { strictJson } from '../domain/json';
export async function atomicWrite(path: string, data: string | Buffer, current = () => true) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 }); const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    const file = await open(temporary, 'wx', 0o600);
    try { await file.writeFile(data); await file.sync(); } finally { await file.close(); }
    if (!current()) throw new AppError('CANCELLED');
    await rename(temporary, path);
    // Directory fsync is supported on Unix; Windows rename durability is covered by platform tests.
    if (process.platform !== 'win32') { const folder = await open(dirname(path), 'r'); try { await folder.sync(); } finally { await folder.close(); } }
  } finally { await rm(temporary, { force: true }); }
}
export interface Cipher { available(): boolean; encrypt(text: string): Buffer; decrypt(buffer: Buffer): string; }
export class SecureStore<T> {
  mode: 'encrypted' | 'memory' | 'locked' = 'memory';
  private queue: Promise<unknown> = Promise.resolve();
  private memory: T | null = null;
  constructor(private path: string, private cipher: Cipher, private validate: (raw: unknown) => T) {}
  private serialize<R>(op: () => Promise<R>): Promise<R> { const result = this.queue.then(op); this.queue = result.catch(() => {}); return result; }
  load(): Promise<T | null> {
    return this.serialize(async () => {
      let data: Buffer; try { data = await readFile(this.path); } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw new AppError('STORAGE_FAILED'); this.mode = this.cipher.available() ? 'encrypted' : 'memory'; return null; }
      if (!this.cipher.available()) { this.mode = 'locked'; throw new AppError('STORAGE_LOCKED'); }
      try { this.memory = this.validate(strictJson(this.cipher.decrypt(data), 32 * 1024 * 1024)); this.mode = 'encrypted'; return this.memory; }
      catch { this.mode = 'locked'; throw new AppError('STORAGE_LOCKED'); }
    });
  }
  save(data: T, current = () => true): Promise<void> {
    return this.serialize(async () => {
      if (!current()) throw new AppError('CANCELLED');
      if (this.mode === 'locked') throw new AppError('STORAGE_LOCKED');
      if (!this.cipher.available()) { this.mode = 'memory'; this.memory = data; return; }
      try { const encrypted = this.cipher.encrypt(JSON.stringify(data)); await atomicWrite(this.path, encrypted, current); if (current()) this.memory = data; this.mode = 'encrypted'; }
      catch (e) { if (e instanceof AppError) throw e; throw new AppError('STORAGE_FAILED'); }
    });
  }
  clear(): Promise<void> { return this.serialize(async () => { await rm(this.path, { force: true }); this.memory = null; this.mode = this.cipher.available() ? 'encrypted' : 'memory'; }); }
}
export class JsonStore<T> {
  private queue: Promise<unknown> = Promise.resolve();
  constructor(private path: string, private validate: (raw: unknown) => T, private maxBytes = 2 * 1024 * 1024) {}
  async load(): Promise<T | null> { try { return this.validate(strictJson(await readFile(this.path, 'utf8'), this.maxBytes)); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null; throw new AppError('STORAGE_FAILED'); } }
  save(data: T, current = () => true) { const result = this.queue.then(() => atomicWrite(this.path, JSON.stringify(data), current)); this.queue = result.catch(() => {}); return result; }
}
