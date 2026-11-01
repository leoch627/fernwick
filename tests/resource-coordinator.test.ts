import { afterEach, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ResourceCoordinator, ResourceCacheSchema, type ResourceCache } from '../src/services/resource-coordinator';
import { JsonStore } from '../src/services/storage';
import { PolicyService } from '../src/services/policy';
import type { HttpResponse, Transport } from '../src/services/http';
import type { Rules } from '../src/domain/compiler';
import { build, now, policy, envelope, deferred } from './fixtures';
const baseline: Rules = { schemaVersion: 2, sections: [{ target: 'direct', domains: ['domain:baseline.cn'] }] };
const direct = (rules: Rules) => rules.sections[0]?.domains?.map(value => value.slice('domain:'.length));
const configured = { ...build, trustedResourceOrigins: ['https://rules.example.invalid'] };
const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map(path => rm(path, { recursive: true, force: true }))); });
function candidate(version: number, domains = ['new.cn'], id = `rules-${version}`) {
  const body = JSON.stringify({ ...baseline, sections: [{ target: 'direct', domains: domains.map(value => `domain:${value}`) }] });
  const descriptor = { id, version, url: `https://rules.example.invalid/${id}.json`, sha256: createHash('sha256').update(body).digest('hex'), bytes: Buffer.byteLength(body), expiresAt: new Date(now + 3600000).toISOString() };
  const signed = envelope({ ...policy, policyVersion: version, routing: { ...policy.routing, resource: descriptor } });
  return { body, descriptor, signed };
}
async function setup(http: Transport, clock = () => now) {
  const directory = await mkdtemp(join(tmpdir(), 'starrail-rules-')); directories.push(directory);
  const path = join(directory, 'rules.json'); const store = new JsonStore(path, raw => ResourceCacheSchema.parse(raw));
  return { path, store, resources: new ResourceCoordinator(configured, baseline, store, http, clock) };
}
const response = (body: string): HttpResponse => ({ status: 200, headers: {}, body });
it('AC-52 validates exact signed bytes, persists them, and re-verifies on restart before expiry fallback', async () => {
  const value = candidate(1); let clock = now;
  const { resources, store } = await setup({ request: async () => response(value.body) }, () => clock);
  await resources.apply(value.signed); expect(direct(resources.rules)).toEqual(['new.cn']); expect(resources.fingerprint).toBe(value.descriptor.sha256);
  expect((await store.load())?.body).toBe(value.body);
  const restarted = new ResourceCoordinator(configured, baseline, store, { request: async () => { throw new Error(); } }, () => clock);
  await restarted.restore(); expect(restarted.rules).toEqual(resources.rules);
  clock += 3600000; expect(restarted.rules).toEqual(baseline); expect(restarted.status).toBe('使用内置大陆分流规则');
});
it('AC-52 a broken routing download does not hold back independently verified control policy', async () => {
  const first = candidate(1), second = candidate(2, ['changed.cn']); let body = first.body;
  const { resources } = await setup({ request: async () => response(body) }); await resources.apply(first.signed);
  const controls = new PolicyService(configured, async () => {}, () => now); await controls.accept(first.signed);
  body = 'truncated'; await controls.accept(second.signed); await resources.apply(second.signed);
  expect(controls.active?.policyVersion).toBe(2); expect(direct(resources.rules)).toEqual(['new.cn']); expect(resources.status).toContain('未验证');
});
it('resource identities and the version high water survive reverting to baseline and restarting', async () => {
  let value = candidate(1); let calls = 0;
  const http = { request: async () => { calls++; return response(value.body); } };
  const { resources, store } = await setup(http); await resources.apply(value.signed);
  value = candidate(2, ['newer.cn']); await resources.apply(value.signed); await resources.apply(envelope({ ...policy, policyVersion: 3 }));
  const restarted = new ResourceCoordinator(configured, baseline, store, http, () => now); await restarted.restore(); expect(restarted.rules).toEqual(baseline);
  value = candidate(4, ['replacement.cn'], 'rules-1'); await restarted.apply(value.signed);
  value = candidate(1); await restarted.apply(value.signed); expect(restarted.rules).toEqual(baseline); expect(calls).toBe(2);
});
it('a superseded response cannot overwrite the next resource or its persisted cache', async () => {
  const first = candidate(1), second = candidate(2, ['current.cn']); const pending = deferred<HttpResponse>(); const started = deferred<void>();
  const { resources, store } = await setup({ request: async input => { if (input.url === first.descriptor.url) { started.resolve(); return pending.promise; } return response(second.body); } });
  const old = resources.apply(first.signed); await started.promise; const current = resources.apply(second.signed);
  pending.resolve(response(first.body)); await Promise.all([old, current]); expect(direct(resources.rules)).toEqual(['current.cn']); expect((await store.load())?.body).toBe(second.body);
});
it('a disk failure retains the prior rules and does not advance their high water', async () => {
  let value = candidate(1); const { resources, store } = await setup({ request: async () => response(value.body) }); await resources.apply(value.signed);
  const original = store.save.bind(store); store.save = async () => { throw new Error('disk full'); };
  value = candidate(2, ['next.cn']); await resources.apply(value.signed); expect(direct(resources.rules)).toEqual(['new.cn']);
  store.save = original; await resources.apply(value.signed); expect(direct(resources.rules)).toEqual(['next.cn']);
});
it('a corrupted persisted resource falls back without trusting its cached hash or contents', async () => {
  const value = candidate(1); const { resources, store, path } = await setup({ request: async () => response(value.body) }); await resources.apply(value.signed);
  const saved: ResourceCache = JSON.parse(await readFile(path, 'utf8')); saved.body = value.body.replace('new.cn', 'bad.cn'); await writeFile(path, JSON.stringify(saved));
  const restarted = new ResourceCoordinator(configured, baseline, store, { request: async () => { throw new Error(); } }, () => now); await restarted.restore(); expect(restarted.rules).toEqual(baseline);
});
it('unknown signing keys or off-list resource sources are rejected before fetching', async () => {
  let calls = 0; const { resources } = await setup({ request: async () => { calls++; throw new Error(); } }); const value = candidate(1);
  await resources.apply(value.signed.replace('"p1"', '"unknown"'));
  await resources.apply(envelope({ ...policy, routing: { ...policy.routing, resource: { ...value.descriptor, url: 'https://other.invalid/rules' } } }));
  expect(calls).toBe(0); expect(resources.rules).toEqual(baseline);
});
