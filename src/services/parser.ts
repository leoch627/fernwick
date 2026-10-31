import { Worker } from 'node:worker_threads';
import type { ParserOptions } from '../domain/subscription';
import type { ParsedNodes } from '../domain/model';
import { AppError } from '../shared/errors';
export function parseInWorker(workerPath: string, raw: string, options: ParserOptions, signal?: AbortSignal): Promise<ParsedNodes> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new AppError('CANCELLED')); return; }
    const worker = new Worker(workerPath, { workerData: { raw, options }, resourceLimits: { maxOldGenerationSizeMb: 96 } });
    const finish = () => { clearTimeout(timer); signal?.removeEventListener('abort', cancel); void worker.terminate(); };
    const cancel = () => { finish(); reject(new AppError('CANCELLED')); };
    const timer = setTimeout(() => { finish(); reject(new AppError('SUBSCRIPTION_INVALID')); }, 3000);
    signal?.addEventListener('abort', cancel, { once: true });
    worker.once('message', (result: { ok: boolean; parsed: ParsedNodes }) => { finish(); if (result.ok) resolve(result.parsed); else reject(new AppError('SUBSCRIPTION_INVALID')); });
    worker.once('error', () => { finish(); reject(new AppError('SUBSCRIPTION_INVALID')); });
    worker.once('exit', code => { if (code !== 0) { finish(); reject(new AppError('SUBSCRIPTION_INVALID')); } });
  });
}
