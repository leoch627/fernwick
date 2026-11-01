import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { brandConfig } from '../tools/brand';
import { helperRoot, helperSocket } from '../src/domain/identity';
import type { BuildConfig } from '../src/shared/schema';

const base = JSON.parse(readFileSync('config/development.json', 'utf8')) as BuildConfig;
const key = () => generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
const brand = () => ({
  id: 'moon-cloud', name: '月云加速', api: ['https://api.mooncloud.net/', 'https://backup.mooncloud.org'],
  endpoint: 'https://updates.mooncloud.net', publicKey: key(),
});

it('builds a valid production configuration from a brand', () => {
  const config = brandConfig(brand(), base);
  expect(config).toMatchObject({ productId: 'moon-cloud', appId: 'app.moon-cloud', name: '月云加速', environment: 'production', channel: 'stable' });
  expect(config.apiEndpoints).toEqual([
    { id: 'primary', baseUrl: 'https://api.mooncloud.net', priority: 10 },
    { id: 'backup', baseUrl: 'https://backup.mooncloud.org', priority: 20 },
  ]);
  expect(config.updateFeedUrls).toEqual(['https://updates.mooncloud.net/v1/release']);
  expect(config.policyUrls).toEqual(['https://updates.mooncloud.net/v1/policy']);
  expect(config.trustedWebOrigins).toContain('https://updates.mooncloud.net');
  expect(config.links.website).toBe('https://api.mooncloud.net/');
  expect(config.protocolCapabilities).toHaveLength(5);
  expect(config.policyKeys).toEqual(config.updateKeys);
});

it('lists several endpoint domains in failover order', () => {
  const config = brandConfig({ ...brand(), endpoint: ['https://dl.mooncloud.net/', 'https://dl.mooncloud.org', 'https://dl.mooncloud.net'] }, base);
  expect(config.updateFeedUrls).toEqual(['https://dl.mooncloud.net/v1/release', 'https://dl.mooncloud.org/v1/release']);
  expect(config.policyUrls).toEqual(['https://dl.mooncloud.net/v1/policy', 'https://dl.mooncloud.org/v1/policy']);
  expect(config.trustedUpdateOrigins).toEqual(['https://dl.mooncloud.net', 'https://dl.mooncloud.org']);
  expect(config.trustedResourceOrigins).toEqual(config.trustedUpdateOrigins);
});

it('serves files from separate download domains while the endpoint stays an API', () => {
  const config = brandConfig({ ...brand(), endpoint: ['https://api.mooncloud.net', 'https://api.mooncloud.org'], downloads: ['https://get.mooncloud.net', 'https://get.mooncloud.org'] }, base);
  expect(config.updateFeedUrls).toEqual(['https://api.mooncloud.net/v1/release', 'https://api.mooncloud.org/v1/release']);
  expect(config.trustedUpdateOrigins).toEqual(['https://get.mooncloud.net', 'https://get.mooncloud.org']);
  expect(config.trustedResourceOrigins).toEqual(config.trustedUpdateOrigins);
  expect(config.trustedWebOrigins).toEqual(expect.arrayContaining(['https://get.mooncloud.net', 'https://api.mooncloud.net']));
});

it('derives system names from the stable id, not the display name', () => {
  const config = brandConfig({ ...brand(), name: '新名字' }, base);
  expect(helperSocket(config, 'linux')).toBe('/run/moon-cloud/helper.sock');
  expect(helperSocket(config, 'win32')).toBe('\\\\.\\pipe\\moon-cloud.helper.v1');
  expect(helperRoot(config, 'C:\\Program Files\\新名字', 'win32')).toMatch(/moon-cloud-service$/);
  expect(helperRoot(config, '/Applications/新名字.app', 'darwin')).toBe('/Library/PrivilegedHelperTools/app.moon-cloud.helper');
});

it.each([
  ['uppercase id', { id: 'MoonCloud' }],
  ['path in id', { id: '../moon' }],
  ['quote in name', { name: 'Moon "Cloud"' }],
  ['slash in name', { name: 'Moon/Cloud' }],
  ['plain http api', { api: ['http://api.mooncloud.net'] }],
  ['no api', { api: [] }],
  ['placeholder host', { endpoint: 'https://updates.example.com' }],
  ['not a public key', { publicKey: 'ssh-ed25519 AAAA' }],
  ['unknown field', { extra: true }],
])('rejects %s', (_name, change: Record<string, unknown>) => {
  const input: Record<string, unknown> = { ...brand(), ...change };
  expect(() => brandConfig(input, base)).toThrow();
});
