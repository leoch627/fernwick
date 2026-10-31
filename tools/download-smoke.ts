/** Real TLS/HTTP streaming test; all traffic and temporary certificates stay on loopback. */
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createServer } from 'node:https';
import { once } from 'node:events';
import { spawnSync } from 'node:child_process';
import tls from 'node:tls';
import { ArtifactDownload, HttpsDownloadTransport } from '../src/services/download';
import { verifyRelease, type Artifact } from '../src/services/update';
import { BuildSchema } from '../src/shared/schema';
import development from '../config/development.json';
async function main() {
  const directory = await mkdtemp(resolve('work/download-smoke-'));
  const originalCAs = tls.getCACertificates('default'); const bytes = Buffer.alloc(512 * 1024, 0x41);
  const requests: { range: string | undefined; ifRange: string | undefined; auth: boolean }[] = [];
  const server = createServer(); let download: ArtifactDownload | null = null;
  try {
    const keyFile = join(directory, 'key.pem'), certFile = join(directory, 'cert.pem');
    assert.equal(spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']).status, 0);
    const certificate = await readFile(certFile, 'utf8'); server.setSecureContext({ key: await readFile(keyFile), cert: certificate });
    tls.setDefaultCACertificates([...originalCAs, certificate]);
    server.on('request', (request, response) => {
      if (request.url === '/redirect') { response.writeHead(302, { location: '/artifact' }); response.end(); return; }
      requests.push({ range: request.headers.range, ifRange: typeof request.headers['if-range'] === 'string' ? request.headers['if-range'] : undefined, auth: !!(request.headers.authorization || request.headers.cookie) });
      const offset = request.headers.range ? Number(/^bytes=(\d+)-$/.exec(request.headers.range)?.[1]) : 0;
      response.writeHead(offset ? 206 : 200, { 'content-length': bytes.length - offset, etag: '"fixture-v1"', ...(offset ? { 'content-range': `bytes ${offset}-${bytes.length - 1}/${bytes.length}` } : {}) });
      if (requests.length === 1) response.write(bytes.subarray(0, 65536)); // Hold the body until pause closes the socket.
      else response.end(bytes.subarray(offset));
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening'); const origin = `https://127.0.0.1:${(server.address() as { port: number }).port}`;
    const keys = generateKeyPairSync('ed25519'); const build = BuildSchema.parse({ ...development, trustedUpdateOrigins: [origin], updateKeys: { fixture: keys.publicKey.export({ format: 'pem', type: 'spki' }) } });
    const artifact: Artifact = { id: 'tls-test', version: '0.2.0', platform: 'linux', arch: 'x64', format: 'deb', minimumOS: '24.04', url: `${origin}/artifact`, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), unpackedBytes: 1024, backupBytes: 1024, coreVersion: '26.10.29', coreSha256: '0'.repeat(64), helperProtocol: 1, signatureIdentity: 'ephemeral-test-only' };
    const payload = Buffer.from(JSON.stringify({ schemaVersion: 1, productId: build.productId, environment: build.environment, channel: build.channel, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString(), releaseSequence: 1, artifacts: [artifact], withdrawnIds: [] }));
    const signed = JSON.stringify({ keyId: 'fixture', payload: payload.toString('base64url'), signature: sign(null, Buffer.concat([Buffer.from('v2board-client-release-v1\n'), payload]), keys.privateKey).toString('base64url') });
    const verified = verifyRelease(signed, build, null, Date.now()).index.artifacts[0]!;
    let partial!: () => void; const gotPartial = new Promise<void>(resolve => { partial = resolve; });
    download = new ArtifactDownload(join(directory, 'updates'), build); download.onChange(() => { if (download!.view.received >= 65536) partial(); });
    await download.select(verified); const first = download.start(); const timeout = setTimeout(() => partial(), 5000);
    try { await gotPartial; assert.equal(download.view.received, 65536); } finally { clearTimeout(timeout); await download.pause(); await first; }
    assert.equal(download.view.status, 'paused'); await download.start(); assert.equal(download.view.status, 'ready');
    assert.equal(requests.length, 2); assert.equal(requests[1]!.range, 'bytes=65536-'); assert.equal(requests[1]!.ifRange, '"fixture-v1"'); assert(requests.every(value => !value.auth));
    const ready = await download.verifiedPath(verified); assert.deepEqual(await readFile(ready), bytes);
    await writeFile(ready, Buffer.alloc(bytes.length)); await assert.rejects(download.verifiedPath(verified));
    const transport = new HttpsDownloadTransport(); const redirected = await transport.open(`${origin}/redirect`, 0, null, new AbortController().signal);
    assert.equal(redirected.status, 302); redirected.close(); assert.equal(requests.length, 2);
    tls.setDefaultCACertificates(originalCAs);
    await assert.rejects(transport.open(`${origin}/artifact`, 0, null, new AbortController().signal));
    console.log('Real HTTPS update smoke passed: signed metadata, streaming pause, Range + If-Range resume, exact byte/hash check, tamper rejection, no redirects or account credentials, untrusted TLS rejection. No installer executed.');
  } finally {
    await download?.pause(); tls.setDefaultCACertificates(originalCAs); server.closeAllConnections(); if (server.listening) await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true });
  }
}
void main().catch(error => { console.error(error); process.exitCode = 1; });
