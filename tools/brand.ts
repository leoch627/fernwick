/**
 * Turn a small brand description into a complete production build configuration.
 *
 *   npm run brand -- config/brand.json [--out work/build-config.json]
 *   BRAND_ID=... BRAND_NAME=... npm run brand                      (CI: values from the environment)
 *
 * Then build with STARRAIL_BUILD_CONFIG pointing at the output.
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { z } from 'zod';
import { strictJson } from '../src/domain/json';
import { validateBuild } from '../src/domain/trust';
import { appIdPattern, displayNamePattern, productIdPattern } from '../src/domain/identity';
import type { BuildConfig } from '../src/shared/schema';
import { KEY_ID } from './signing';

const https = z.string().url().refine(v => new URL(v).protocol === 'https:', 'must be https');
const pem = z.string().includes('-----BEGIN PUBLIC KEY-----');
export const BrandSchema = z.object({
  id: z.string().regex(productIdPattern, 'lowercase letters, digits and hyphens, 3-40 characters'),
  name: z.string().regex(displayNamePattern, 'up to 64 characters, no quotes or path characters'),
  appId: z.string().regex(appIdPattern).max(120).optional(),
  api: z.array(https).min(1).max(8),
  subscriptionOrigins: z.array(https).max(8).default([]),
  website: https.optional(), renew: https.optional(), help: https.optional(),
  /** Customer service chat, e.g. https://go.crisp.chat/chat/embed/?website_id=… */
  support: https.optional(),
  /** Update endpoint origin, or several domains of it in failover order (the first is the one CI publishes to). */
  endpoint: z.union([https, z.array(https).min(1).max(4)]),
  /** Download domain(s) for the download page, installers, update archives and rule files, in failover order. Defaults to the endpoint. */
  downloads: z.union([https, z.array(https).min(1).max(4)]).optional(),
  publicKey: pem,
}).strict();
export type Brand = z.infer<typeof BrandSchema>;

const origin = (url: string) => new URL(url).origin;
const unique = (values: string[]) => [...new Set(values)];

export function brandConfig(input: unknown, base: Pick<BuildConfig, 'healthTargets' | 'hardLimits'>): BuildConfig {
  const brand = BrandSchema.parse(input);
  const endpoints = unique((Array.isArray(brand.endpoint) ? brand.endpoint : [brand.endpoint]).map(origin));
  const downloads = brand.downloads ? unique((Array.isArray(brand.downloads) ? brand.downloads : [brand.downloads]).map(origin)) : endpoints;
  const website = brand.website ?? `${origin(brand.api[0]!)}/`;
  const api = brand.api.map(url => url.replace(/\/+$/, ''));
  return validateBuild({
    schemaVersion: 2, productId: brand.id, appId: brand.appId ?? `app.${brand.id}`, name: brand.name,
    environment: 'production', channel: 'stable', tenantId: brand.id,
    adapterId: 'v2board-explicit-v1', deploymentVerified: true, subscriptionFormatId: 'v2ray-uri-base64-v1',
    apiEndpoints: api.map((baseUrl, i) => ({ id: i === 0 ? 'primary' : i === 1 ? 'backup' : `backup-${i}`, baseUrl, priority: (i + 1) * 10 })),
    trustedSubscriptionOrigins: unique([...api.map(origin), ...brand.subscriptionOrigins.map(origin)]),
    trustedWebOrigins: unique([...api.map(origin), ...[website, brand.renew, brand.help, brand.support].filter((v): v is string => !!v).map(origin), ...endpoints, ...downloads]),
    trustedResourceOrigins: downloads, trustedUpdateOrigins: downloads,
    policyUrls: endpoints.map(e => `${e}/v1/policy`), updateFeedUrls: endpoints.map(e => `${e}/v1/release`),
    links: { website, renew: brand.renew ?? website, help: brand.help ?? website, support: brand.support ?? null },
    // One key signs both; the purpose prefix in each signature keeps policy and release index apart.
    policyKeys: { [KEY_ID]: brand.publicKey }, updateKeys: { [KEY_ID]: brand.publicKey },
    protocolCapabilities: ['vless-tls', 'vless-reality', 'vmess-ws-tls', 'trojan-tls', 'shadowsocks-aead'],
    nodeCapabilitiesConfirmed: true, allowUnverifiedNodeTrials: false,
    healthTargets: base.healthTargets, hardLimits: base.hardLimits,
  });
}

function fromEnvironment(env: NodeJS.ProcessEnv) {
  const list = (value?: string) => (value ?? '').split(/[\s,]+/).filter(Boolean);
  const optional = (value?: string) => value?.trim() || undefined;
  return {
    id: env.BRAND_ID, name: env.BRAND_NAME, appId: optional(env.BRAND_APP_ID),
    api: [...list(env.BRAND_API_PRIMARY), ...list(env.BRAND_API_BACKUP)],
    subscriptionOrigins: list(env.BRAND_SUBSCRIPTION_ORIGINS),
    website: optional(env.BRAND_WEBSITE), support: optional(env.BRAND_SUPPORT), endpoint: list(env.BRAND_ENDPOINT),
    downloads: list(env.BRAND_DOWNLOADS).length ? list(env.BRAND_DOWNLOADS) : undefined,
    publicKey: env.BRAND_PUBLIC_KEY,
  };
}

async function main() {
  const args = process.argv.slice(2); const at = args.indexOf('--out');
  const out = at >= 0 ? args.splice(at, 2)[1] : 'work/build-config.json';
  const input = args[0] ? strictJson(await readFile(args[0], 'utf8')) : fromEnvironment(process.env);
  const base = strictJson(await readFile('config/development.json', 'utf8')) as BuildConfig;
  const config = brandConfig(input, base);
  await mkdir(dirname(out!), { recursive: true });
  await writeFile(out!, JSON.stringify(config, null, 2) + '\n');
  console.log(`Wrote ${out}: ${config.name} (${config.productId}), API ${config.apiEndpoints.map(e => e.baseUrl).join(' / ')}, updates ${config.updateFeedUrls.join(' / ')}, downloads ${config.trustedUpdateOrigins.join(' / ')}`);
}
if (process.argv[1]?.endsWith('brand.ts')) void main().catch(error => {
  console.error(error instanceof z.ZodError ? `Brand rejected:\n${error.issues.map(i => `  ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n')}` : `Brand rejected: ${(error as Error).message}`);
  process.exitCode = 1;
});
