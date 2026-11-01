/** Real upstream core integration, all traffic confined to loopback. No TUN is started. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer as createNetServer, type Socket } from 'node:net';
import os from 'node:os';
import { createServer } from 'node:https';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { resolve, join } from 'node:path';
import tls from 'node:tls';
import { CoreRuntime } from '../src/platform/core';
import { compileTun } from '../src/domain/core-config';
import { parseSubscription } from '../src/domain/subscription';
import lock from '../resources/core-lock.json';
import type { ProxyNode } from '../src/domain/model';

async function checkX25519Hello(runtime: CoreRuntime, input: ProxyNode) {
  const sockets = new Set<Socket>(); let captured!: (value: Buffer) => void;
  const hello = new Promise<Buffer>(resolve => { captured = resolve; });
  const listener = createNetServer(socket => {
    sockets.add(socket); let received = Buffer.alloc(0);
    socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    socket.on('data', bytes => {
      received = Buffer.concat([received, bytes]); if (received.length > 65536) { socket.destroy(); return; }
      if (received.length >= 5 && received.length >= 5 + received.readUInt16BE(3)) captured(received.subarray(0, 5 + received.readUInt16BE(3)));
    });
  });
  listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
  const abort = new AbortController(); const deadline = setTimeout(() => abort.abort(), 3000);
  const emptyHash = createHash('sha256').update('').digest('hex');
  const task = runtime.probe({ ...input, host: '127.0.0.1', port: (listener.address() as { port: number }).port }, [
    { url: 'https://localhost/unused-one', status: 204, bodySha256: emptyHash }, { url: 'https://localhost/unused-two', status: 204, bodySha256: emptyHash },
  ], abort.signal).catch(() => null);
  try {
    const record = await Promise.race([hello, new Promise<never>((_, reject) => abort.signal.addEventListener('abort', () => reject(new Error('No ClientHello')), { once: true }))]);
    assert.equal(record[0], 22); assert.equal(record[5], 1); // TLS handshake / ClientHello.
    let offset = 9 + 2 + 32; offset += 1 + record[offset]!;
    offset += 2 + record.readUInt16BE(offset); offset += 1 + record[offset]!;
    const end = offset + 2 + record.readUInt16BE(offset); offset += 2; const shares: number[] = [];
    while (offset < end) {
      const kind = record.readUInt16BE(offset), length = record.readUInt16BE(offset + 2); offset += 4;
      if (kind === 51) { let at = offset + 2; const last = at + record.readUInt16BE(offset); while (at < last) { const group = record.readUInt16BE(at), size = record.readUInt16BE(at + 2); shares.push(group); at += 4 + size; } }
      offset += length;
    }
    const actual = shares.filter(group => (group & 0x0f0f) !== 0x0a0a); // Ignore GREASE placeholders.
    assert.deepEqual(actual, [29], 'Default ClientHello must send an X25519 share, not an invalid fingerprint or PQ replacement');
  } finally { clearTimeout(deadline); abort.abort(); await task; sockets.forEach(socket => socket.destroy()); await new Promise<void>(resolve => listener.close(() => resolve())); }
}

async function port() { const s = createNetServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const a = s.address() as { port: number }; await new Promise<void>(r => s.close(() => r())); return a.port; }
async function stop(child: ChildProcess) { if (child.exitCode !== null || child.signalCode !== null) return; child.kill(); const timer = setTimeout(() => child.kill('SIGKILL'), 500); await once(child, 'exit'); clearTimeout(timer); }
async function main() {
const root = resolve('resources/native'), target = `${process.platform}-${process.arch}`;
const asset = lock.assets.find(a => a.target === target); assert(asset);
const executable = join(root, target, asset.executable); const runtime = await CoreRuntime.load(root);
const temporary = await mkdtemp(resolve('work/core-smoke-')); const children: ChildProcess[] = [];
const before = Object.keys(os.networkInterfaces()).sort();
const oldCertificates = tls.getCACertificates('default'); let server: ReturnType<typeof createServer> | null = null;
try {
  const keyFile = join(temporary, 'key.pem'), certFile = join(temporary, 'cert.pem');
  const cert = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']); assert.equal(cert.status, 0);
  const certificate = await readFile(certFile, 'utf8');
  // An ephemeral test CA, never installed in the host trust store or shipped in the app.
  tls.setDefaultCACertificates([...oldCertificates, certificate]);
  let requests = 0; server = createServer({ key: await readFile(keyFile), cert: certificate }, (req, res) => { requests++; if (req.url === '/hang') return; res.writeHead(204); res.end(); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); const webPort = (server.address() as { port: number }).port;
  const ssPort = await port(); const password = randomBytes(24).toString('hex');
  const serverConfig = { log: { loglevel: 'none', access: 'none', error: 'none' }, inbounds: [{ protocol: 'shadowsocks', listen: '127.0.0.1', port: ssPort, settings: { method: 'aes-128-gcm', password, network: 'tcp,udp' } }], outbounds: [{ protocol: 'freedom', settings: { finalRules: [{ action: 'allow', ip: ['127.0.0.1/32'] }] } }] };
  const process = spawn(executable, ['run', '-format', 'json', '-config', 'stdin:'], { stdio: ['pipe', 'ignore', 'ignore'], env: { LANG: 'C' } }); children.push(process); process.stdin!.end(JSON.stringify(serverConfig)); await new Promise(r => setTimeout(r, 150));
  const options = { source: 'local-core-smoke', capabilities: ['vless-tls', 'vless-reality', 'vmess-ws-tls', 'trojan-tls', 'shadowsocks-aead'] as const, confirmedTcpUdp: true };
  const ss = `ss://${Buffer.from('aes-128-gcm:' + password).toString('base64url')}@127.0.0.1:${ssPort}#local`;
  const vless = 'vless://00000000-0000-4000-8000-000000000001@localhost:443?security=tls&type=tcp&sni=localhost';
  const vmess = 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'test', add: 'localhost', port: '443', id: '00000000-0000-4000-8000-000000000001', aid: '0', net: 'ws', path: '/', host: 'localhost', tls: 'tls', scy: 'auto' })).toString('base64');
  const nodes = [ss, vless, vless.replace('security=tls', 'security=reality&pbk=' + 'A'.repeat(43) + '&sid=1234&flow=xtls-rprx-vision'), vmess, 'trojan://test@localhost:443?security=tls&type=tcp&sni=localhost'].map(uri => parseSubscription(uri, options).nodes[0]!);
  for (const node of nodes) {
    assert(node.compatible); await runtime.check(node, new AbortController().signal);
    const config = compileTun(node, 'rule', { schemaVersion: 2, sections: [{ target: 'proxy', domains: ['domain:force.example.cn'] }, { target: 'direct', domains: ['domain:example.cn'] }] }, {
      platform: processPlatform(), interface: 'lo', resolvedNodeAddress: '127.0.0.1', bootstrapDns: 'https://223.5.5.5/dns-query', proxyDns: 'https://1.1.1.1/dns-query',
    }, { port: await port(), user: 'test', password: 'test-long-random-session' });
    const check = spawnSync(executable, ['run', '-test', '-format', 'json', '-config', 'stdin:'], { input: JSON.stringify(config), timeout: 3000, env: { LANG: 'C' } });
    assert.equal(check.status, 0, `TUN syntax rejected for ${node.protocol}/${node.security}: ${check.stdout}`);
  }
  const baseline = JSON.parse(await readFile('resources/rules/baseline.json', 'utf8'));
  const full = compileTun(nodes[1]!, 'rule', baseline, { platform: processPlatform(), interface: 'lo', resolvedNodeAddress: '127.0.0.1', bootstrapDns: 'https://223.5.5.5/dns-query', proxyDns: 'https://1.1.1.1/dns-query' }, { port: await port(), user: 'test', password: 'test-long-random-session' });
  const fullCheck = spawnSync(executable, ['run', '-test', '-format', 'json', '-config', 'stdin:'], { input: JSON.stringify(full), timeout: 5000, env: { LANG: 'C' } });
  assert.equal(fullCheck.status, 0, `Complete bundled CN routing dataset rejected: ${fullCheck.stdout}`);
  await checkX25519Hello(runtime, nodes[1]!);
  const empty = createHash('sha256').update('').digest('hex');
  const targets = [{ url: `https://localhost:${webPort}/health`, status: 204, bodySha256: empty }, { url: `https://localhost:${webPort}/second-domain-in-production`, status: 204, bodySha256: empty }];
  // Use IPv4 explicitly; this host need not have a loopback IPv6 listener.
  targets.forEach(t => { t.url = t.url.replace('localhost', '127.0.0.1'); });
  const result = await runtime.probe(nodes[0]!, targets, new AbortController().signal); assert.equal(result.healthy, true); assert(requests > 0);
  const beforeFallback = requests;
  assert.equal((await runtime.probe(nodes[0]!, [{ ...targets[0]!, status: 200 }, targets[1]!], new AbortController().signal)).healthy, true); assert(requests >= beforeFallback + 2);
  assert.equal((await runtime.probe(nodes[0]!, targets.map(t => ({ ...t, bodySha256: '0'.repeat(64) })), new AbortController().signal)).healthy, false);
  const during = new AbortController(); const deadline = setTimeout(() => during.abort(), 500);
  try { await assert.rejects(runtime.probe(nodes[0]!, targets.map(t => ({ ...t, url: `https://127.0.0.1:${webPort}/hang` })), during.signal)); }
  finally { clearTimeout(deadline); }
  tls.setDefaultCACertificates(oldCertificates);
  assert.equal((await runtime.probe(nodes[0]!, targets, new AbortController().signal)).healthy, false, 'Untrusted TLS must fail');
  const abort = new AbortController(); abort.abort(); await assert.rejects(runtime.probe(nodes[0]!, targets, abort.signal));
  assert.deepEqual(Object.keys(os.networkInterfaces()).sort(), before);
  console.log('Real Xray smoke passed: 5 protocol configuration checks, complete TUN syntax with bundled CN dataset, captured default X25519 ClientHello key share, encrypted Shadowsocks -> authenticated SOCKS -> verified HTTPS, second-target fallback, body-hash rejection, untrusted TLS rejection, cancellation. No TUN/OS network changes.');
} finally {
  tls.setDefaultCACertificates(oldCertificates); for (const child of children) await stop(child);
  if (server) { server.closeAllConnections(); await new Promise<void>(r => server!.close(() => r())); }
  await rm(temporary, { recursive: true, force: true });
}
function processPlatform(): 'linux' | 'darwin' | 'win32' { assert(['linux', 'darwin', 'win32'].includes(process.platform)); return process.platform as 'linux' | 'darwin' | 'win32'; }
}
void main().catch(error => { console.error(error); process.exitCode = 1; });
