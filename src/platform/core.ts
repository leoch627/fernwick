import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { createConnection, createServer, isIP, type Socket } from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import { AppError, assert } from '../shared/errors';
import { Budget } from '../domain/time';
import { compileProbe } from '../domain/core-config';
import type { ProxyNode } from '../domain/model';
import type { ProbeResult } from '../domain/selection';
import lock from '../../resources/core-lock.json';

export interface ProbeTarget { url: string; status: number; bodySha256: string; }
export interface ProbeCredentials { port: number; user: string; password: string; }

/** This executor is for unprivileged, isolated probes. It cannot start TUN or arbitrary JSON. */
export class CoreRuntime {
  private constructor(readonly executable: string, private digest: string, private helper: { path: string; sha256: string } | null = null) {}
  static async load(root: string, inventory?: { components: { target: string; type: string; sha256: string }[] }) {
    const target = `${process.platform}-${process.arch}`;
    const asset = lock.assets.find(a => a.target === target) as (typeof lock.assets[number] & { executableSha256?: string }) | undefined;
    assert(asset?.executableSha256, 'COMPONENTS_UNAVAILABLE');
    const helper = inventory?.components.find(c => c.type === 'helper' && c.target === target);
    const runtime = new CoreRuntime(join(root, target, asset.executable), inventory?.components.find(c => c.type === 'core' && c.target === target)?.sha256 ?? asset.executableSha256, helper ? { path: join(root, target, process.platform === 'win32' ? 'helper.exe' : 'helper'), sha256: helper.sha256 } : null);
    await runtime.verify(); return runtime;
  }
  private async verify() {
    try {
      const file = await lstat(this.executable);
      assert(file.isFile() && !file.isSymbolicLink() && file.size < 100 * 1024 * 1024, 'COMPONENTS_UNAVAILABLE');
      assert(process.platform === 'win32' || !(file.mode & 0o022), 'COMPONENTS_UNAVAILABLE');
      const hash = createHash('sha256'); for await (const chunk of createReadStream(this.executable)) hash.update(chunk);
      assert(hash.digest('hex') === this.digest, 'COMPONENTS_UNAVAILABLE');
      if (this.helper) { const helper = await lstat(this.helper.path); assert(helper.isFile() && !helper.isSymbolicLink() && helper.size < 64 * 1024 * 1024, 'COMPONENTS_UNAVAILABLE'); const sum = createHash('sha256'); for await (const chunk of createReadStream(this.helper.path)) sum.update(chunk); assert(sum.digest('hex') === this.helper.sha256, 'COMPONENTS_UNAVAILABLE'); }
    } catch { throw new AppError('COMPONENTS_UNAVAILABLE'); }
  }
  private launch(configuration: ReturnType<typeof compileProbe>, test: boolean, signal: AbortSignal) {
    if (signal.aborted) throw new AppError('CANCELLED');
    const bytes = JSON.stringify(configuration); assert(Buffer.byteLength(bytes) <= 2 * 1024 * 1024);
    // Do not inherit XRAY_CONF*, proxy variables, Lua/plugin paths, or secret environment values.
    const env: NodeJS.ProcessEnv = { LANG: 'C', XRAY_LOCATION_ASSET: dirname(this.executable) };
    if (process.platform === 'win32') { env.SystemRoot = process.env.SystemRoot; env.WINDIR = process.env.WINDIR; }
    const child = spawn(this.helper?.path ?? this.executable, this.helper ? ['probe-core', String(process.pid), ...(test ? ['--check'] : [])] : ['run', ...(test ? ['-test'] : []), '-format', 'json', '-config', 'stdin:'], {
      shell: false, windowsHide: true, cwd: dirname(this.executable), env, stdio: ['pipe', 'ignore', 'ignore'],
    });
    let code: number | null = null;
    const exited = new Promise<number | null>(resolve => { child.once('error', () => resolve(null)); child.once('exit', value => { code = value; resolve(value); }); });
    child.stdin!.on('error', () => {}); child.stdin!.end(bytes);
    const abort = () => child.kill('SIGTERM'); signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const onExit = () => child.kill('SIGKILL'); process.once('exit', onExit);
    const stop = async () => {
      signal.removeEventListener('abort', abort); process.removeListener('exit', onExit);
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill('SIGTERM'); const hard = setTimeout(() => child.kill('SIGKILL'), 300);
      try { await Promise.race([exited, new Promise<never>((_, reject) => setTimeout(() => reject(new AppError('COMPONENTS_UNAVAILABLE')), 1000).unref())]); }
      finally { clearTimeout(hard); }
    };
    return { child, exited, stop, get code() { return code; } };
  }
  async check(node: ProxyNode, signal: AbortSignal) {
    await this.verify();
    const config = compileProbe(node, { port: 49151, user: 'check', password: 'check-only-not-a-session' });
    const budget = new Budget(2500, signal); let running: ReturnType<CoreRuntime['launch']> | null = null;
    try { await budget.run(async s => { running = this.launch(config, true, s); assert(await running.exited === 0, 'NO_COMPATIBLE_NODES'); }); }
    finally { budget.cancel(); budget.dispose(); if (running) await (running as ReturnType<CoreRuntime['launch']>).stop(); }
  }
  async probe(node: ProxyNode, targets: readonly ProbeTarget[], signal: AbortSignal): Promise<ProbeResult> {
    assert(targets.length >= 2 && targets.length <= 3, 'CONFIGURATION_REQUIRED');
    for (const target of targets) {
      const url = new URL(target.url);
      assert(url.protocol === 'https:' && !url.username && !url.password && !url.hash && !url.search && /^[a-f0-9]{64}$/.test(target.bodySha256) && Number.isInteger(target.status) && target.status >= 200 && target.status <= 299, 'CONFIGURATION_REQUIRED');
    }
    const budget = new Budget(5500, signal); let running: ReturnType<CoreRuntime['launch']> | null = null;
    try {
      return await budget.run(async s => {
        await this.verify(); if (s.aborted) throw new AppError('CANCELLED');
        const auth = { port: await availablePort(), user: randomBytes(16).toString('hex'), password: randomBytes(24).toString('base64url') };
        running = this.launch(compileProbe(node, auth), false, s);
        await waitForListener(auth.port, running.child, s);
        // Try a second failure domain before calling the node unhealthy; each target has its own cap.
        for (const target of targets) {
          const attempt = new Budget(Math.min(2000, budget.remaining), s); const start = performance.now();
          try { await attempt.run(a => probeHttps(auth, target, a)); return { healthy: true, latencyMs: Math.round(performance.now() - start) }; }
          catch { if (s.aborted) throw new AppError('CANCELLED'); }
          finally { attempt.cancel(); attempt.dispose(); }
        }
        return { healthy: false, latencyMs: null };
      });
    } finally { budget.cancel(); budget.dispose(); if (running) await (running as ReturnType<CoreRuntime['launch']>).stop(); }
  }
}

async function availablePort(): Promise<number> {
  const server = createServer();
  return new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { const address = server.address(); if (!address || typeof address === 'string') { server.close(); reject(new AppError('COMPONENTS_UNAVAILABLE')); return; } server.close(error => error ? reject(error) : resolve(address.port)); }); });
}
async function waitForListener(port: number, child: ChildProcess, signal: AbortSignal) {
  while (!signal.aborted && child.exitCode === null && child.signalCode === null) {
    try { const socket = await openSocket(port, signal); socket.destroy(); return; }
    catch { if (signal.aborted) break; await new Promise(resolve => setTimeout(resolve, 25)); }
  }
  throw new AppError(signal.aborted ? 'CANCELLED' : 'COMPONENTS_UNAVAILABLE');
}
function openSocket(port: number, signal: AbortSignal): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port, signal });
    socket.once('error', reject); socket.once('connect', () => resolve(socket));
  });
}
async function readBytes(socket: Socket, count: number, signal: AbortSignal): Promise<Buffer> {
  if (signal.aborted) throw new AppError('CANCELLED');
  return new Promise((resolve, reject) => {
    const done = (error?: Error, bytes?: Buffer) => { socket.off('readable', read); socket.off('error', fail); socket.off('end', ended); socket.off('close', ended); signal.removeEventListener('abort', abort); error ? reject(error) : resolve(bytes!); };
    const read = () => { const value = socket.read(count) as Buffer | null; if (value) done(undefined, value); };
    const fail = () => done(new AppError('CONNECT_TIMEOUT'));
    const ended = () => done(new AppError('CONNECT_TIMEOUT'));
    const abort = () => { socket.destroy(); done(new AppError('CANCELLED')); };
    socket.on('readable', read); socket.once('error', fail); socket.once('end', ended); socket.once('close', ended); signal.addEventListener('abort', abort, { once: true }); read();
  });
}
export async function probeHttps(auth: ProbeCredentials, target: ProbeTarget, signal: AbortSignal) {
  const url = new URL(target.url); const socket = await openSocket(auth.port, signal); let secure: tls.TLSSocket | null = null; let agent: https.Agent | null = null;
  try {
    socket.write(Buffer.from([5, 1, 2])); assert((await readBytes(socket, 2, signal)).equals(Buffer.from([5, 2])), 'CONNECT_TIMEOUT');
    const user = Buffer.from(auth.user), pass = Buffer.from(auth.password); assert(user.length <= 255 && pass.length <= 255);
    socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    assert((await readBytes(socket, 2, signal)).equals(Buffer.from([1, 0])), 'CONNECT_TIMEOUT');
    const hostname = Buffer.from(url.hostname); assert(hostname.length <= 255);
    const port = Buffer.alloc(2); port.writeUInt16BE(Number(url.port || 443));
    socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, hostname.length]), hostname, port]));
    const reply = await readBytes(socket, 4, signal); assert(reply[0] === 5 && reply[1] === 0 && reply[2] === 0, 'CONNECT_TIMEOUT');
    const addressSize = reply[3] === 1 ? 4 : reply[3] === 4 ? 16 : reply[3] === 3 ? (await readBytes(socket, 1, signal))[0]! : 0;
    assert(addressSize > 0, 'CONNECT_TIMEOUT'); await readBytes(socket, addressSize + 2, signal);
    secure = tls.connect({ socket, host: url.hostname, servername: isIP(url.hostname) ? undefined : url.hostname,
      checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(url.hostname, certificate), rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] });
    secure.on('error', () => {});
    agent = new https.Agent({ keepAlive: false, maxSockets: 1 }); agent.createConnection = () => secure!;
    await new Promise<void>((resolve, reject) => {
      let size = 0; const hash = createHash('sha256');
      const request = https.request(url, { method: 'GET', agent: agent!, signal, headers: { 'User-Agent': 'v2board-client-health/0.1', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store', 'Connection': 'close' } }, response => {
        if (response.statusCode !== target.status) { response.destroy(); reject(new AppError('CONNECT_TIMEOUT')); return; }
        response.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 65536) { response.destroy(); reject(new AppError('CONNECT_TIMEOUT')); } else hash.update(chunk); });
        response.once('error', () => reject(new AppError('CONNECT_TIMEOUT')));
        response.once('end', () => { if (hash.digest('hex') === target.bodySha256) resolve(); else reject(new AppError('CONNECT_TIMEOUT')); });
      });
      request.once('error', () => reject(new AppError(signal.aborted ? 'CANCELLED' : 'CONNECT_TIMEOUT'))); request.end();
    });
  } finally { agent?.destroy(); secure?.destroy(); socket.destroy(); }
}
