import { parentPort, workerData } from 'node:worker_threads';
import { parseSubscription } from '../domain/subscription';
try { parentPort?.postMessage({ ok: true, parsed: parseSubscription(workerData.raw, workerData.options) }); }
catch { parentPort?.postMessage({ ok: false }); }
