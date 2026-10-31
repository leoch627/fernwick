import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { beforeEach, expect, it } from 'vitest';
import worker, { renew, type Env, type R2BucketLike } from '../server/src/index';
import { adminToken } from '../server/src/signing';
import { brandConfig } from '../tools/brand';
import { verifyRelease, selectUpdate } from '../src/services/update';
import { checkWatermark, verifyPolicy } from '../src/services/policy';
import { validateResource } from '../src/services/resources';
import type { BuildConfig } from '../src/shared/schema';

const base = JSON.parse(readFileSync('config/development.json', 'utf8')) as BuildConfig;
const pair = () => { const k = generateKeyPairSync('ed25519'); return { private: k.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), public: k.publicKey.export({ type: 'spki', format: 'pem' }).toString() }; };
const signingKey = pair();
const ORIGIN = 'https://updates.mooncloud.net';
const build = brandConfig({ id: 'moon-cloud', name: '月云加速', api: ['https://api.mooncloud.net', 'https://backup.mooncloud.org'], endpoint: ORIGIN, publicKey: signingKey.public }, base);
// The Worker escapes whatever name it is given; the client build itself forbids markup characters.
const brand = { productId: build.productId, name: '月云 & <Co>', environment: build.environment, channel: build.channel, endpointIds: build.apiEndpoints.map(e => e.id), links: build.links as { website: string; renew: string; help: string } };

class MemoryBucket implements R2BucketLike {
  objects = new Map<string, Uint8Array>();
  set(key: string, data: Uint8Array | string) { this.objects.set(key, typeof data === 'string' ? new TextEncoder().encode(data) : data); }
  private meta(key: string, data: Uint8Array) { return { size: data.length, httpEtag: `"${createHash('md5').update(data).digest('hex')}"`, key }; }
  async head(key: string) { const data = this.objects.get(key); return data ? this.meta(key, data) : null; }
  async get(key: string, options?: { range?: { offset: number; length?: number } }) {
    const data = this.objects.get(key); if (!data) return null;
    const slice = options?.range ? data.subarray(options.range.offset, options.range.length === undefined ? undefined : options.range.offset + options.range.length) : data;
    return { ...this.meta(key, data), body: new Response(new Uint8Array(slice)).body!, text: async () => new TextDecoder().decode(slice) };
  }
  async put(key: string, value: string) { this.set(key, value); }
}

let bucket: MemoryBucket, env: Env, token: string;
const call = (path: string, init: RequestInit & { token?: string } = {}) => worker.fetch(new Request(`${ORIGIN}${path}`, {
  ...init, headers: { ...(init.token !== undefined ? { authorization: `Bearer ${init.token}` } : {}), ...(init.body ? { 'content-type': 'application/json' } : {}), ...init.headers as Record<string, string> },
}), env);
const installer = new Uint8Array(4096).map((_, i) => i % 251);
const sha = (data: Uint8Array) => createHash('sha256').update(data).digest('hex');
const file = (key: string, platform: string, arch: string, format: string, signatureIdentity = 'unsigned') => ({
  key, platform, arch, format, bytes: installer.length, sha256: sha(installer), unpackedBytes: 10000, minimumOS: platform === 'linux' ? '24.04' : platform === 'win32' ? '10.0.22000' : '14.0',
  coreVersion: '26.10.31', coreSha256: 'c'.repeat(64), signatureIdentity,
});
const files = [
  file('releases/0.2.0/app-linux-amd64.deb', 'linux', 'x64', 'deb'),
  file('releases/0.2.0/app-win-x64.exe', 'win32', 'x64', 'nsis'),
  file('releases/0.2.0/app-mac-arm64.dmg', 'darwin', 'arm64', 'dmg'),
  file('releases/0.2.0/app-mac-arm64.zip', 'darwin', 'arm64', 'zip'),
];
const publish = (body: unknown = { brand, version: '0.2.0', files }, bearer = token) => call('/admin/release', { method: 'POST', token: bearer, body: JSON.stringify(body) });

beforeEach(async () => {
  bucket = new MemoryBucket();
  for (const f of files) bucket.set(f.key, installer);
  env = { FILES: bucket, SIGNING_KEY: signingKey.private };
  token = await adminToken(signingKey.private);
});

it('publishes a release index the client verifies and selects from', async () => {
  expect((await call('/v1/release')).status).toBe(404);
  const published = await publish();
  expect(published.status).toBe(200);
  const raw = await (await call('/v1/release')).text();
  const { index } = verifyRelease(raw, build, null, Date.now());
  expect(index.artifacts.map(a => a.id).sort()).toEqual(['darwin-arm64-zip-0.2.0', 'linux-x64-deb-0.2.0', 'win32-x64-nsis-0.2.0']);
  const linux = selectUpdate(index, { platform: 'linux', arch: 'x64', version: '0.1.0', osCompatible: () => true });
  expect(linux?.url).toBe(`${ORIGIN}/files/releases/0.2.0/app-linux-amd64.deb`);
  expect(selectUpdate(index, { platform: 'darwin', arch: 'arm64', version: '0.1.0', osCompatible: () => true })?.format).toBe('zip');
  expect(selectUpdate(index, { platform: 'linux', arch: 'x64', version: '0.2.0', osCompatible: () => true })).toBeNull();
});

it('serves a policy the client accepts, and carries rule updates', async () => {
  expect((await call('/admin/rules', { method: 'POST', token, body: JSON.stringify({ key: 'rules/x/rules.json', sha256: 'a'.repeat(64), bytes: 1 }) })).status).toBe(400);
  await publish();
  const first = verifyPolicy(await (await call('/v1/policy')).text(), build, null, Date.now());
  expect(first.policy.routing.resource).toBeNull();
  expect(first.policy.links).toEqual(build.links);

  const rules = new TextEncoder().encode(JSON.stringify({ schemaVersion: 1, directDomains: ['cn'], proxyDomains: [], blockedDomains: [], directIPs: ['1.0.1.0/24'] }));
  bucket.set('rules/20261031/rules.json', rules);
  const response = await call('/admin/rules', { method: 'POST', token, body: JSON.stringify({ key: 'rules/20261031/rules.json', sha256: sha(rules), bytes: rules.length }) });
  expect(response.status).toBe(200);
  const second = verifyPolicy(await (await call('/v1/policy')).text(), build, first.watermark, Date.now());
  const resource = second.policy.routing.resource!;
  expect(resource.url).toBe(`${ORIGIN}/files/rules/20261031/rules.json`);
  const served = new Uint8Array(await (await call('/files/rules/20261031/rules.json')).arrayBuffer());
  expect(validateResource(Buffer.from(served), resource, build, Date.now()).directDomains).toEqual(['cn']);
});

it('re-signs with increasing sequences the client accepts as newer', async () => {
  await publish();
  const before = verifyRelease(await (await call('/v1/release')).text(), build, null, Date.now());
  await renew(env, Date.now() + 6 * 3600_000);
  const later = Date.now() + 6 * 3600_000;
  const after = verifyRelease(await (await call('/v1/release')).text(), build, null, later);
  expect(after.watermark.version).toBeGreaterThan(before.watermark.version);
  expect(() => checkWatermark(before.watermark, after.watermark)).not.toThrow();
  // A fresh policy is not re-signed until it nears expiry; rule descriptors stay stable.
  expect((await renew(env, Date.now() + 3600_000)).policy).toBe(false);
  expect((await renew(env, Date.now() + 30 * 3600_000)).policy).toBe(true);
});

it('derives the admin token from the signing key, independent of PEM line wrapping', async () => {
  expect(token).toMatch(/^[a-f0-9]{64}$/);
  expect(await adminToken(signingKey.private.replace(/\n/g, '\r\n'))).toBe(token);
  expect(await adminToken(pair().private)).not.toBe(token);
  expect((await call('/admin/status', { token: await adminToken(pair().private) })).status).toBe(401);
  expect((await call('/admin/status', { token })).status).toBe(200);
});

it('rejects unauthenticated and inconsistent publishing', async () => {
  expect((await publish(undefined, 'wrong')).status).toBe(401);
  expect((await call('/admin/status')).status).toBe(401);
  bucket.objects.delete(files[0]!.key);
  expect((await publish()).status).toBe(400);
  bucket.set(files[0]!.key, installer);
  for (const body of [
    { brand, version: 'latest', files },
    { brand, version: '0.2.0', files: [{ ...files[0], key: 'state/release.json' }] },
    { brand, version: '0.2.0', files: [{ ...files[0], platform: 'linux', format: 'dmg' }] },
    { brand, version: '0.2.0', files: [files[0], files[0]] },
    { brand: { ...brand, links: { ...brand.links, website: 'http://insecure.net' } }, version: '0.2.0', files },
  ]) expect((await publish(body)).status).toBe(400);
});

it('keeps serving the installed brand: renames pass, another product is refused', async () => {
  expect((await publish()).status).toBe(200);
  expect((await publish({ brand: { ...brand, name: '月云' }, version: '0.2.0', files })).status).toBe(200);
  const other = await publish({ brand: { ...brand, productId: 'other-cloud' }, version: '0.2.0', files });
  expect(other.status).toBe(400);
  expect(await other.text()).toContain('separate endpoint');
  expect((await publish({ brand: { ...brand, environment: 'test', channel: 'test' }, version: '0.2.0', files })).status).toBe(400);
  expect(verifyPolicy(await (await call('/v1/policy')).text(), build, null, Date.now()).policy.productId).toBe(build.productId);
});

it('serves resumable downloads but never signing state', async () => {
  await publish();
  const key = '/files/releases/0.2.0/app-linux-amd64.deb';
  const full = await call(key);
  const etag = full.headers.get('etag')!;
  expect(full.status).toBe(200);
  expect(etag).toMatch(/^"[^"]+"$/);
  const partial = await call(key, { headers: { range: 'bytes=4000-', 'if-range': etag } });
  expect(partial.status).toBe(206);
  expect(partial.headers.get('content-range')).toBe('bytes 4000-4095/4096');
  expect(new Uint8Array(await partial.arrayBuffer())).toEqual(installer.subarray(4000));
  expect((await call(key, { headers: { range: 'bytes=4000-', 'if-range': '"stale"' } })).status).toBe(200);
  expect((await call(key, { headers: { range: 'bytes=5000-' } })).status).toBe(416);
  expect((await call('/files/state/release.json')).status).toBe(404);
  expect((await call('/files/releases/../state/release.json')).status).toBe(404);
});

it('renders an escaped download page', async () => {
  await publish();
  const html = await (await call('/')).text();
  expect(html).toContain('月云 &#38; &#60;Co&#62;');
  expect(html).not.toContain('<Co>');
  expect(html).toContain('/files/releases/0.2.0/app-mac-arm64.dmg');
  expect(html).toContain('xattr -dr com.apple.quarantine');
});
