import { importSigningKey, sameSecret, signEnvelope } from './signing';
import {
  InputError, nextSequence, parseRelease, parseRules, policyPayload, releaseArtifacts, releasePayload, POLICY_RENEW_MS,
  type Brand, type PolicyState, type ReleaseState,
} from './payloads';
import { downloadPage } from './page';

// The subset of the Workers R2 API this service uses.
export interface R2ObjectLike { size: number; httpEtag: string; uploaded?: Date }
export interface R2BodyLike extends R2ObjectLike { body: ReadableStream; text(): Promise<string> }
export interface R2BucketLike {
  head(key: string): Promise<R2ObjectLike | null>;
  get(key: string, options?: { range?: { offset: number; length?: number } }): Promise<R2BodyLike | null>;
  put(key: string, value: string, options?: { httpMetadata?: { contentType?: string } }): Promise<unknown>;
}
export interface Env {
  FILES: R2BucketLike;
  /** PKCS#8 PEM private keys; their public halves are the brand's updatePublicKey / policyPublicKey. */
  RELEASE_SIGNING_KEY: string; POLICY_SIGNING_KEY: string;
  ADMIN_TOKEN: string;
  /** Public origin clients use, e.g. https://updates.example.net. Defaults to the request origin. */
  PUBLIC_ORIGIN?: string;
}

const STATE = { brand: 'state/brand.json', release: 'state/release.json', policy: 'state/policy.json' } as const;
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });

async function load<T>(env: Env, key: string): Promise<T | null> {
  const object = await env.FILES.get(key);
  return object ? JSON.parse(await object.text()) as T : null;
}
const save = (env: Env, key: string, value: unknown) => env.FILES.put(key, JSON.stringify(value), { httpMetadata: { contentType: 'application/json' } });

async function signRelease(env: Env, brand: Brand, state: Omit<ReleaseState, 'sequence' | 'envelope' | 'signedAt'> & { sequence?: number }, now: number): Promise<ReleaseState> {
  const sequence = nextSequence(state.sequence ?? 0, now);
  const envelope = await signEnvelope(await importSigningKey(env.RELEASE_SIGNING_KEY), 'release-1', 'v2board-client-release-v1', releasePayload(brand, { ...state, sequence }, now));
  const signed: ReleaseState = { ...state, sequence, envelope, signedAt: new Date(now).toISOString() };
  await save(env, STATE.release, signed);
  return signed;
}
async function signPolicy(env: Env, brand: Brand, previous: PolicyState | null, rules: PolicyState['rules'], now: number): Promise<PolicyState> {
  const version = nextSequence(previous?.version ?? 0, now);
  const payload = policyPayload(brand, version, rules, now);
  const envelope = await signEnvelope(await importSigningKey(env.POLICY_SIGNING_KEY), 'policy-1', 'v2board-client-policy-v1', payload);
  const signed: PolicyState = { version, rules, envelope, signedAt: new Date(now).toISOString(), expiresAt: payload.expiresAt };
  await save(env, STATE.policy, signed);
  return signed;
}

/** Keep envelopes inside their validity windows. Runs from the cron trigger and on demand. */
export async function renew(env: Env, now = Date.now(), force = false) {
  const brand = await load<Brand>(env, STATE.brand); if (!brand) return { release: false, policy: false };
  const release = await load<ReleaseState>(env, STATE.release), policy = await load<PolicyState>(env, STATE.policy);
  if (release) await signRelease(env, brand, release, now);
  const renewPolicy = force || !policy || Date.parse(policy.expiresAt) - now < POLICY_RENEW_MS;
  if (renewPolicy) await signPolicy(env, brand, policy, policy?.rules ?? null, now);
  return { release: !!release, policy: renewPolicy };
}

async function serveFile(request: Request, env: Env, key: string): Promise<Response> {
  // Only published files are public; state/ holds signing state.
  if (!/^(releases|rules)\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(key)) return new Response('Not found', { status: 404 });
  const head = await env.FILES.head(key); if (!head) return new Response('Not found', { status: 404 });
  const headers = new Headers({
    'accept-ranges': 'bytes', etag: head.httpEtag, 'content-type': key.startsWith('rules/') ? 'application/json' : 'application/octet-stream',
    'cache-control': 'public, max-age=31536000, immutable', 'content-disposition': `attachment; filename="${key.split('/').pop()}"`,
  });
  const match = /^bytes=(\d+)-(\d*)$/.exec(request.headers.get('range') ?? '');
  const ifRange = request.headers.get('if-range');
  if (match && (!ifRange || ifRange === head.httpEtag)) {
    const start = Number(match[1]), end = match[2] ? Math.min(Number(match[2]), head.size - 1) : head.size - 1;
    if (start >= head.size || end < start) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${head.size}` } });
    headers.set('content-range', `bytes ${start}-${end}/${head.size}`); headers.set('content-length', String(end - start + 1));
    if (request.method === 'HEAD') return new Response(null, { status: 206, headers });
    const object = await env.FILES.get(key, { range: { offset: start, length: end - start + 1 } });
    return object ? new Response(object.body, { status: 206, headers }) : new Response('Not found', { status: 404 });
  }
  headers.set('content-length', String(head.size));
  if (request.method === 'HEAD') return new Response(null, { headers });
  const object = await env.FILES.get(key);
  return object ? new Response(object.body, { headers }) : new Response('Not found', { status: 404 });
}

async function admin(request: Request, env: Env, path: string, origin: string, now: number): Promise<Response> {
  const token = /^Bearer (.+)$/.exec(request.headers.get('authorization') ?? '')?.[1] ?? '';
  if (!await sameSecret(token, env.ADMIN_TOKEN)) return json({ error: 'unauthorized' }, 401);
  let body: unknown = null;
  if (request.method === 'POST') { try { body = await request.json(); } catch { return json({ error: 'invalid json' }, 400); } }
  try {
    if (path === '/admin/release' && request.method === 'POST') {
      const input = parseRelease(body);
      for (const file of input.files) {
        const head = await env.FILES.head(file.key);
        if (!head || head.size !== file.bytes) throw new InputError(`${file.key} is missing or has a different size in R2`);
      }
      await save(env, STATE.brand, input.brand);
      const previous = await load<ReleaseState>(env, STATE.release);
      const release = await signRelease(env, input.brand, {
        sequence: previous?.sequence, version: input.version, publishedAt: new Date(now).toISOString(),
        artifacts: releaseArtifacts(origin, input.version, input.files),
        downloads: input.files.map(f => ({ file: f.key, platform: f.platform, arch: f.arch, format: f.format, bytes: f.bytes, sha256: f.sha256, signed: f.signatureIdentity !== 'unsigned' })),
        withdrawnIds: previous?.withdrawnIds ?? [],
      }, now);
      const policy = await load<PolicyState>(env, STATE.policy);
      // A brand change (links, endpoints) must reach clients through a new policy.
      await signPolicy(env, input.brand, policy, policy?.rules ?? null, now);
      return json({ version: release.version, sequence: release.sequence, artifacts: release.artifacts.length });
    }
    if (path === '/admin/rules' && request.method === 'POST') {
      const input = parseRules(body);
      const brand = await load<Brand>(env, STATE.brand); if (!brand) throw new InputError('publish a release first');
      const head = await env.FILES.head(input.key);
      if (!head || head.size !== input.bytes) throw new InputError(`${input.key} is missing or has a different size in R2`);
      const previous = await load<PolicyState>(env, STATE.policy);
      // The client binds a rule ID to one hash, so the ID is derived from the hash.
      const rules = { id: `cn-rules-${input.sha256.slice(0, 16)}`, version: nextSequence(previous?.rules?.version ?? 0, now), url: `${origin}/files/${input.key}`, sha256: input.sha256, bytes: input.bytes };
      const policy = await signPolicy(env, brand, previous, rules, now);
      return json({ policyVersion: policy.version, rules: rules.id });
    }
    if (path === '/admin/renew' && request.method === 'POST') return json(await renew(env, now, true));
    if (path === '/admin/status' && request.method === 'GET') {
      const [brand, release, policy] = await Promise.all([load<Brand>(env, STATE.brand), load<ReleaseState>(env, STATE.release), load<PolicyState>(env, STATE.policy)]);
      return json({ brand, release: release && { version: release.version, sequence: release.sequence, signedAt: release.signedAt, artifacts: release.artifacts.map(a => a.id) }, policy: policy && { version: policy.version, signedAt: policy.signedAt, expiresAt: policy.expiresAt, rules: policy.rules } });
    }
    return json({ error: 'not found' }, 404);
  } catch (error) {
    if (error instanceof InputError) return json({ error: error.message }, 400);
    throw error;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url), origin = (env.PUBLIC_ORIGIN || url.origin).replace(/\/+$/, ''), now = Date.now();
    if (url.pathname.startsWith('/admin/')) return admin(request, env, url.pathname, origin, now);
    if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method not allowed', { status: 405 });
    if (url.pathname === '/v1/release' || url.pathname === '/v1/policy') {
      const state = await load<{ envelope: string }>(env, url.pathname === '/v1/release' ? STATE.release : STATE.policy);
      return state ? new Response(state.envelope, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } }) : json({ error: 'not published' }, 404);
    }
    if (url.pathname.startsWith('/files/')) return serveFile(request, env, decodeURIComponent(url.pathname.slice('/files/'.length)));
    if (url.pathname === '/' || url.pathname === '/download') {
      const [brand, release] = await Promise.all([load<Brand>(env, STATE.brand), load<ReleaseState>(env, STATE.release)]);
      return new Response(downloadPage(brand, release), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=60', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'" } });
    }
    return new Response('Not found', { status: 404 });
  },
  async scheduled(_event: unknown, env: Env): Promise<void> { await renew(env); },
};
