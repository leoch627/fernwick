import { connect } from 'node:net';
import { randomUUID, createHash, verify, createPublicKey } from 'node:crypto';
import { readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { z } from 'zod';
import { AppError, messages, type ErrorCode } from '../shared/errors';
import type { BuildConfig } from '../shared/schema';
import type { NetworkDriver } from './network';
import type { HttpRequest, HttpResponse, Transport } from '../services/http';
import { DirectHttpsTransport } from '../services/http';
import type { Budget } from '../domain/time';
import type { Artifact } from '../services/update';
import type { ProxyNode } from '../domain/model';
import { RulesSchema } from '../domain/compiler';
import { helperRoot, helperSocket } from '../domain/identity';
const execute = promisify(execFile);
const Reply = z.object({ id: z.string(), ok: z.boolean(), error: z.string().optional(), protocol: z.literal(1), productId: z.string(), buildId: z.string(), version: z.string(), state: z.string(), ready: z.boolean(), owned: z.boolean(), ticket: z.string().optional(), signature: z.string().optional(), proof: z.object({ tcp: z.boolean(), udp: z.boolean(), dns: z.boolean(), ipv6: z.boolean() }).optional(), http: z.object({ status: z.number().int(), headers: z.record(z.string(), z.string()), body: z.string() }).optional() }).strict();
type Reply = z.infer<typeof Reply>;
export interface NativeManifest { buildId: string; components: { target: string; type: string; file: string; sha256: string }[]; }
export class NativeDriver implements NetworkDriver {
  verified = false;
  private ticket = ''; private heartbeat: ReturnType<typeof setInterval> | null = null; private beatRunning = false;
  private deadline = 0; private installRunning: Promise<void> | null = null; private closing = false;
  constructor(private build: BuildConfig, private manifest: NativeManifest, private resources: string, private appRoot: string, private packaged: boolean, private failed: (code: ErrorCode) => void) {}
  private get socket() { return helperSocket(this.build); }
  private async rpc(action: string, input: Record<string, unknown> = {}, signal?: AbortSignal): Promise<Reply> {
    if (signal?.aborted) throw new AppError('CANCELLED');
    if (process.platform !== 'win32') { const stat = await lstat(this.socket).catch(() => null); if (!stat?.isSocket() || stat.uid !== 0) throw new AppError('COMPONENTS_UNAVAILABLE'); }
    const identityRoot = helperRoot(this.build, this.appRoot);
    const publicKey = createPublicKey(await readFile(join(identityRoot, 'server-public.pem'))); if (publicKey.asymmetricKeyType !== 'ed25519') throw new AppError('COMPONENTS_UNAVAILABLE');
    const id = randomUUID(), challenge = randomUUID(), helloId = randomUUID(); let authenticated = false;
    return new Promise((resolve, reject) => {
      const socket = connect(this.socket); let length = 0; const chunks: Buffer[] = []; let settled = false;
      const done = (error?: AppError, value?: Reply) => { if (settled) return; settled = true; signal?.removeEventListener('abort', abort); socket.destroy(); error ? reject(error) : resolve(value!); };
      const abort = () => done(new AppError('CANCELLED')); signal?.addEventListener('abort', abort, { once: true });
      socket.setTimeout(action === 'stage-update' ? 120000 : action === 'heartbeat' ? 1800 : 11500, () => done(new AppError('COMPONENTS_UNAVAILABLE')));
      socket.once('connect', () => socket.write(JSON.stringify({ protocol: 1, productId: this.build.productId, id: helloId, action: 'hello', challenge }) + '\n'));
      socket.on('data', (chunk: Buffer) => {
        length += chunk.length; if (length > 72 * 1024 * 1024) { done(new AppError('COMPONENTS_UNAVAILABLE')); return; } chunks.push(chunk);
        if (chunk.includes(10)) { try {
          const reply = Reply.parse(JSON.parse(Buffer.concat(chunks).toString('utf8'))); chunks.length = 0; length = 0;
          if (reply.id !== (authenticated ? id : helloId) || reply.productId !== this.build.productId || reply.buildId !== this.manifest.buildId) throw new Error('identity');
          if (!authenticated) {
            const proof = Buffer.from(`starrail-helper-v1\n${challenge}\n${this.build.productId}\n${this.manifest.buildId}`);
            if (!reply.ok || !reply.signature || !verify(null, proof, publicKey, Buffer.from(reply.signature, 'base64url'))) throw new Error('identity');
            authenticated = true; socket.write(JSON.stringify({ protocol: 1, productId: this.build.productId, id, action, ...input }) + '\n'); return;
          }
          if (!reply.ok) { const code = reply.error && Object.hasOwn(messages, reply.error) ? reply.error as ErrorCode : 'COMPONENTS_UNAVAILABLE'; done(new AppError(code)); } else done(undefined, reply);
        } catch { done(new AppError('COMPONENTS_UNAVAILABLE')); } }
      });
      socket.once('error', () => done(new AppError('COMPONENTS_UNAVAILABLE'))); socket.once('end', () => { if (!settled) done(new AppError('COMPONENTS_UNAVAILABLE')); });
    });
  }
  async initialize() { try { const reply = await this.rpc('status'); this.verified = reply.ready; if (reply.state === 'RecoveryRequired') this.failed('NETWORK_RECOVERY_REQUIRED'); } catch { this.verified = false; } }
  async ensureReady() { await this.initialize(); if (!this.verified) await this.repair(); }
  async repair() {
    if (this.installRunning) return this.installRunning;
    this.installRunning = (async () => {
      if (!this.packaged) throw new AppError('COMPONENTS_UNAVAILABLE');
      if (this.verified) { const status = await this.rpc('status'); if (status.state !== 'Disconnected' && !status.owned) throw new AppError('NETWORK_CONFLICT'); }
      const target = `${process.platform}-${process.arch}`, name = process.platform === 'win32' ? 'helper.exe' : 'helper';
      const helper = join(this.resources, 'native', target, name), pin = this.manifest.components.find(c => c.type === 'helper' && c.target === target);
      if (!pin || createHash('sha256').update(await readFile(helper)).digest('hex') !== pin.sha256) throw new AppError('COMPONENTS_UNAVAILABLE');
      try {
        if (process.platform === 'linux') await execute('/usr/bin/pkexec', [helper, 'install', '--app', this.appRoot], { timeout: 180000, maxBuffer: 4096 });
        else if (process.platform === 'darwin') { const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'"; const command = `${quote(helper)} install --app ${quote(this.appRoot)}`; await execute('/usr/bin/osascript', ['-e', `do shell script ${JSON.stringify(command)} with administrator privileges`], { timeout: 180000, maxBuffer: 4096 }); }
        else if (process.platform === 'win32') {
          const script = `$p=Start-Process -FilePath $env:STARRAIL_HELPER -ArgumentList ('install --app "'+$env:STARRAIL_APP+'"') -Verb RunAs -Wait -PassThru; exit $p.ExitCode`;
          await execute(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile', '-NonInteractive', '-Command', script], { env: { ...process.env, STARRAIL_HELPER: helper, STARRAIL_APP: this.appRoot }, windowsHide: true, timeout: 180000, maxBuffer: 4096 });
        } else throw new Error('platform');
      } catch { throw new AppError('PERMISSION_REQUIRED'); }
      await this.initialize(); if (!this.verified) throw new AppError('COMPONENTS_UNAVAILABLE');
    })().finally(() => { this.installRunning = null; }); return this.installRunning;
  }
  setAuthorizedUntil(deadline: number) { this.deadline = deadline; }
  async prepare(candidate: unknown, signal: AbortSignal) {
    const value = candidate as { node: ProxyNode; mode: string; rules: unknown; authorizedUntil: number };
    RulesSchema.parse(value.rules); this.deadline = value.authorizedUntil; this.closing = false;
    const fields = ['protocol', 'host', 'port', 'credential', 'method', 'transport', 'security', 'sni', 'flow', 'publicKey', 'shortId', 'fingerprint', 'wsPath', 'wsHost'] as const;
    const node = Object.fromEntries(fields.filter(k => value.node[k] !== undefined).map(k => [k, value.node[k]]));
    const reply = await this.rpc('prepare', { candidate: { node, mode: value.mode, rules: value.rules, authorizedUntil: this.deadline } }, signal);
    if (!reply.ticket) throw new AppError('COMPONENTS_UNAVAILABLE'); this.ticket = reply.ticket;
    this.heartbeat = setInterval(() => void this.beat(), 750); this.heartbeat.unref(); return this.ticket;
  }
  private async beat() {
    if (this.beatRunning || !this.ticket || this.closing) return; this.beatRunning = true;
    try { const response = await this.rpc('heartbeat', { ticket: this.ticket, authorizedUntil: this.deadline }); if (!response.owned || response.state === 'Disconnected' || response.state === 'RecoveryRequired') throw new AppError('NETWORK_RECOVERY_REQUIRED'); }
    catch { if (!this.closing) { this.verified = false; this.stopHeartbeat(); this.failed('NETWORK_RECOVERY_REQUIRED'); } }
    finally { this.beatRunning = false; }
  }
  private stopHeartbeat() { if (this.heartbeat) clearInterval(this.heartbeat); this.heartbeat = null; }
  async protect(ticket: string, _deadline: number, signal: AbortSignal) { await this.rpc('protect', { ticket }, signal); }
  async start(ticket: string, signal: AbortSignal) { await this.rpc('start', { ticket }, signal); }
  async probe(ticket: string, signal: AbortSignal) { const reply = await this.rpc('probe', { ticket }, signal); if (!reply.proof) throw new AppError('CONNECT_TIMEOUT'); return reply.proof; }
  async commit(ticket: string, signal: AbortSignal) { await this.rpc('commit', { ticket }, signal); }
  async cleanup(signal: AbortSignal) {
    this.closing = true; this.stopHeartbeat();
    if (!this.ticket && !this.verified) return;
    try { await this.rpc('stop', { ticket: this.ticket }, signal); this.ticket = ''; }
    catch (e) { this.verified = false; throw e; }
  }
  async control(input: HttpRequest, budget: Budget): Promise<HttpResponse> { const reply = await budget.run(signal => this.rpc('control', { http: input }, signal)); if (!reply.http) throw new AppError('CONTROL_UNAVAILABLE'); return reply.http; }
  async install(artifact: Artifact, path: string, envelope: string) { if (!this.verified) throw new AppError('COMPONENTS_UNAVAILABLE'); await this.rpc('stage-update', { artifactId: artifact.id, artifactPath: path, releaseEnvelope: envelope }); }
}
export class HelperTransport implements Transport {
  private direct = new DirectHttpsTransport();
  constructor(private native: NativeDriver) {}
  request(input: HttpRequest, budget: Budget) { return this.native.verified ? this.native.control(input, budget) : this.direct.request(input, budget); }
}
