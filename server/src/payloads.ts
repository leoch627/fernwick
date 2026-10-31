// Release index and policy payloads. Field sets mirror the client's strict schemas:
// ReleaseSchema/ArtifactSchema in src/services/update.ts and PolicySchema in src/shared/schema.ts.

export interface Brand {
  productId: string; name: string; environment: 'production' | 'test'; channel: 'stable' | 'test';
  endpointIds: string[]; links: { website: string; renew: string; help: string };
}
export interface Artifact {
  id: string; version: string; platform: 'win32' | 'darwin' | 'linux'; arch: 'x64' | 'arm64'; format: 'nsis' | 'dmg' | 'zip' | 'deb';
  minimumOS: string; url: string; bytes: number; sha256: string; unpackedBytes: number; backupBytes: number;
  coreVersion: string; coreSha256: string; helperProtocol: 1; signatureIdentity: string;
}
/** Everything shown on the download page, including DMGs the updater does not use. */
export interface Download { file: string; platform: Artifact['platform']; arch: Artifact['arch']; format: Artifact['format']; bytes: number; sha256: string; signed: boolean }
export interface RuleResource { id: string; version: number; url: string; sha256: string; bytes: number; expiresAt: string }

export interface ReleaseState { sequence: number; version: string; publishedAt: string; artifacts: Artifact[]; downloads: Download[]; withdrawnIds: string[]; envelope: string; signedAt: string }
export interface PolicyState { version: number; rules: Omit<RuleResource, 'expiresAt'> | null; envelope: string; signedAt: string; expiresAt: string }

export const RELEASE_VALIDITY_MS = 24 * 3600_000;
export const POLICY_VALIDITY_MS = 72 * 3600_000;
/** Re-sign a policy once less than this remains, so rule descriptors (and downloads) change about daily. */
export const POLICY_RENEW_MS = 48 * 3600_000;
const SKEW_MS = 5 * 60_000;

/** Monotonic sequence: the client rejects an equal sequence with different bytes. */
export const nextSequence = (previous: number, now: number) => Math.max(previous + 1, Math.floor(now / 1000));

export function releasePayload(brand: Brand, state: Pick<ReleaseState, 'sequence' | 'artifacts' | 'withdrawnIds'>, now: number) {
  return {
    schemaVersion: 1, productId: brand.productId, environment: brand.environment, channel: brand.channel,
    issuedAt: new Date(now - SKEW_MS).toISOString(), expiresAt: new Date(now + RELEASE_VALIDITY_MS).toISOString(),
    releaseSequence: state.sequence, artifacts: state.artifacts, withdrawnIds: state.withdrawnIds,
  };
}

export function policyPayload(brand: Brand, version: number, rules: PolicyState['rules'], now: number) {
  const issuedAt = new Date(now - SKEW_MS).toISOString(), expiresAt = new Date(now + POLICY_VALIDITY_MS).toISOString();
  return {
    schemaVersion: 2, policyVersion: version, productId: brand.productId, environment: brand.environment, channel: brand.channel,
    issuedAt, notBefore: issuedAt, expiresAt, requiredCapabilities: [],
    endpoints: { orderedIds: brand.endpointIds, temporarilyDisabledIds: [] },
    refresh: { subscriptionIntervalSec: 1800, accountIntervalSec: 300, policyIntervalSec: 900, maxSnapshotAgeSec: 86400 },
    ui: { expiryReminderDays: [7, 3], showTrafficSummary: true, announcement: null },
    links: brand.links, nodeOperations: [],
    // A rule descriptor may not outlive the policy that carries it.
    routing: { templateId: 'cn-direct-default-proxy-v1', dnsTemplateId: 'real-dns-split-v1', resource: rules ? { ...rules, expiresAt } : null },
    maintenance: null,
    update: { checkIntervalSec: 21600, noticeText: null },
  };
}

// ---- Admin input validation (the CI publish step is the only caller) ----

const hex64 = /^[a-f0-9]{64}$/;
const semver = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const fileKey = /^(releases|rules)\/[A-Za-z0-9._-]{1,64}\/[A-Za-z0-9._-]{1,160}$/;
const formats: Record<Artifact['platform'], Artifact['format'][]> = { win32: ['nsis'], linux: ['deb'], darwin: ['dmg', 'zip'] };

export class InputError extends Error {}
function check(condition: unknown, message: string): asserts condition { if (!condition) throw new InputError(message); }
const httpsUrl = (value: unknown) => { try { return typeof value === 'string' && new URL(value).protocol === 'https:'; } catch { return false; } };

export function parseBrand(input: any): Brand {
  check(input && typeof input === 'object', 'brand required');
  check(/^[a-z][a-z0-9-]{1,38}[a-z0-9]$/.test(input.productId), 'brand.productId');
  check(typeof input.name === 'string' && input.name.length > 0 && input.name.length <= 64, 'brand.name');
  check(['production', 'test'].includes(input.environment) && (input.environment === 'production') === (input.channel === 'stable'), 'brand.environment/channel');
  check(Array.isArray(input.endpointIds) && input.endpointIds.length > 0 && input.endpointIds.length <= 8 && input.endpointIds.every((id: unknown) => typeof id === 'string' && /^[a-z0-9-]{1,32}$/.test(id)), 'brand.endpointIds');
  const links = input.links ?? {};
  check(['website', 'renew', 'help'].every(k => httpsUrl(links[k])), 'brand.links');
  return { productId: input.productId, name: input.name, environment: input.environment, channel: input.channel, endpointIds: [...input.endpointIds], links: { website: links.website, renew: links.renew, help: links.help } };
}

export interface PublishedFile {
  key: string; platform: Artifact['platform']; arch: Artifact['arch']; format: Artifact['format'];
  bytes: number; sha256: string; unpackedBytes: number; minimumOS: string; coreVersion: string; coreSha256: string; signatureIdentity: string;
}
export function parseRelease(input: any): { brand: Brand; version: string; files: PublishedFile[] } {
  check(input && typeof input === 'object', 'body required');
  check(typeof input.version === 'string' && semver.test(input.version), 'version');
  check(Array.isArray(input.files) && input.files.length > 0 && input.files.length <= 16, 'files');
  const files = input.files.map((f: any, i: number): PublishedFile => {
    const at = `files[${i}]`;
    check(typeof f?.key === 'string' && fileKey.test(f.key) && f.key.startsWith(`releases/${input.version}/`), `${at}.key`);
    check(formats[f.platform as Artifact['platform']]?.includes(f.format) && ['x64', 'arm64'].includes(f.arch) && (f.platform === 'darwin' || f.arch === 'x64'), `${at}.platform/arch/format`);
    check(Number.isSafeInteger(f.bytes) && f.bytes > 0 && f.bytes <= 2147483648 && Number.isSafeInteger(f.unpackedBytes) && f.unpackedBytes > 0, `${at}.bytes`);
    check(hex64.test(f.sha256) && hex64.test(f.coreSha256), `${at}.sha256`);
    check(typeof f.minimumOS === 'string' && /^\d+(?:\.\d+){0,3}$/.test(f.minimumOS), `${at}.minimumOS`);
    check(typeof f.coreVersion === 'string' && /^[0-9A-Za-z.+-]{1,64}$/.test(f.coreVersion), `${at}.coreVersion`);
    check(typeof f.signatureIdentity === 'string' && f.signatureIdentity.length > 0 && f.signatureIdentity.length <= 256, `${at}.signatureIdentity`);
    return { key: f.key, platform: f.platform, arch: f.arch, format: f.format, bytes: f.bytes, sha256: f.sha256, unpackedBytes: f.unpackedBytes, minimumOS: f.minimumOS, coreVersion: f.coreVersion, coreSha256: f.coreSha256, signatureIdentity: f.signatureIdentity };
  });
  const targets = files.map((f: PublishedFile) => `${f.platform}-${f.arch}-${f.format}`);
  check(new Set(targets).size === targets.length, 'duplicate platform/arch/format');
  return { brand: parseBrand(input.brand), version: input.version, files };
}

export function parseRules(input: any): { key: string; sha256: string; bytes: number } {
  check(input && typeof input.key === 'string' && fileKey.test(input.key) && input.key.startsWith('rules/'), 'key');
  check(hex64.test(input.sha256), 'sha256');
  check(Number.isSafeInteger(input.bytes) && input.bytes > 0 && input.bytes <= 33554432, 'bytes');
  return { key: input.key, sha256: input.sha256, bytes: input.bytes };
}

/** Updater entries: the client installs NSIS, DEB and (on macOS) ZIP; DMGs are download-page only. */
export function releaseArtifacts(origin: string, version: string, files: PublishedFile[]): Artifact[] {
  return files.filter(f => f.format !== 'dmg').map(f => ({
    id: `${f.platform}-${f.arch}-${f.format}-${version}`, version, platform: f.platform, arch: f.arch, format: f.format,
    minimumOS: f.minimumOS, url: `${origin}/files/${f.key}`, bytes: f.bytes, sha256: f.sha256,
    unpackedBytes: f.unpackedBytes, backupBytes: f.unpackedBytes, coreVersion: f.coreVersion, coreSha256: f.coreSha256,
    helperProtocol: 1, signatureIdentity: f.signatureIdentity,
  }));
}
