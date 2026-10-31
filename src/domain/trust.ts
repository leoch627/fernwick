import { createPublicKey } from 'node:crypto';
import { BuildSchema, type BuildConfig } from '../shared/schema';
import { assert } from '../shared/errors';
export function httpsUrl(raw: string): URL {
  let u: URL; try { u = new URL(raw); } catch { throw new Error('Invalid URL'); }
  assert(u.protocol === 'https:' && !u.username && !u.password && !u.hash, 'INVALID_INPUT');
  assert(!/[\\\u0000-\u0020]/.test(raw) && !/%(?:2f|5c|00)/i.test(u.pathname), 'INVALID_INPUT');
  return u;
}
export function trustedUrl(raw: string, origins: readonly string[]): string {
  const u = httpsUrl(raw);
  assert(origins.some(origin => { const o = httpsUrl(origin); return o.origin === u.origin && o.pathname === '/' && !o.search; }), 'INVALID_INPUT');
  return u.href;
}
export function validateBuild(input: unknown): BuildConfig {
  const config = BuildSchema.parse(input);
  assert((config.environment === 'production') === (config.channel === 'stable'));
  const ids = config.apiEndpoints.map(e => e.id); assert(new Set(ids).size === ids.length);
  const origins = [...config.trustedSubscriptionOrigins, ...config.trustedWebOrigins, ...config.trustedResourceOrigins, ...config.trustedUpdateOrigins];
  origins.forEach(raw => { const u = httpsUrl(raw); assert(u.pathname === '/' && !u.search); });
  config.apiEndpoints.forEach(e => { const u = httpsUrl(e.baseUrl); assert(!u.search); });
  [...config.policyUrls, ...config.updateFeedUrls].forEach(httpsUrl);
  config.healthTargets.forEach(target => { const u = httpsUrl(target.url); assert(!u.search); });
  Object.values(config.links).forEach(link => { if (link) trustedUrl(link, config.trustedWebOrigins); });
  for (const key of [...Object.values(config.policyKeys), ...Object.values(config.updateKeys)]) {
    assert(createPublicKey(key).asymmetricKeyType === 'ed25519');
  }
  if (config.environment === 'production') {
    assert(!config.allowUnverifiedNodeTrials, 'CONFIGURATION_REQUIRED');
    assert(config.healthTargets.length >= 2 && new Set(config.healthTargets.map(target => target.failureDomain)).size >= 2, 'CONFIGURATION_REQUIRED');
    assert(config.deploymentVerified && config.nodeCapabilitiesConfirmed && config.protocolCapabilities.length === 5, 'CONFIGURATION_REQUIRED');
    assert(config.apiEndpoints.length > 0 && config.policyUrls.length > 0 && config.updateFeedUrls.length > 0 && origins.length > 0, 'CONFIGURATION_REQUIRED');
    assert(Object.keys(config.policyKeys).length > 0 && Object.keys(config.updateKeys).length > 0 && Object.values(config.links).every(Boolean), 'CONFIGURATION_REQUIRED');
    assert(!/test|example|unconfigured/i.test(config.appId + config.productId + config.tenantId), 'CONFIGURATION_REQUIRED');
    for (const raw of [...origins, ...config.policyUrls, ...config.updateFeedUrls, ...config.apiEndpoints.map(e => e.baseUrl), ...Object.values(config.links).filter((v): v is string => !!v)]) {
      const host = httpsUrl(raw).hostname;
      assert(!/(^|\.)(example\.(com|org|net)|localhost|invalid|test)$/.test(host) && !host.endsWith('.example') && !host.endsWith('.invalid'), 'CONFIGURATION_REQUIRED');
    }
    const policy = new Set(Object.values(config.policyKeys)); assert(Object.values(config.updateKeys).every(k => !policy.has(k)), 'CONFIGURATION_REQUIRED');
  }
  return config;
}
