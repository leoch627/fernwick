import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { z } from 'zod';
import { gt, valid } from 'semver';
import type { BuildConfig } from '../shared/schema';
import { utc } from '../shared/schema';
import { AppError, assert } from '../shared/errors';
import { trustedUrl } from '../domain/trust';
import { checkWatermark, verifyEnvelope, type Watermark } from './policy';
export const ArtifactSchema = z.object({
  id: z.string().regex(/^[a-zA-Z0-9._-]{1,160}$/), version: z.string().refine(v => !!valid(v)),
  platform: z.enum(['win32', 'darwin', 'linux']), arch: z.enum(['x64', 'arm64']), format: z.enum(['nsis', 'dmg', 'zip', 'deb']),
  minimumOS: z.string().min(1).max(100), url: z.string().url(), bytes: z.number().int().positive().max(2147483648),
  sha256: z.string().regex(/^[a-f0-9]{64}$/), unpackedBytes: z.number().int().positive().safe(), backupBytes: z.number().int().nonnegative().safe(),
  coreVersion: z.string().min(1).max(64), coreSha256: z.string().regex(/^[a-f0-9]{64}$/), helperProtocol: z.literal(1), signatureIdentity: z.string().min(1).max(256),
}).strict();
export type Artifact = z.infer<typeof ArtifactSchema>;
export const ReleaseSchema = z.object({ schemaVersion: z.literal(1), productId: z.string(), environment: z.enum(['test', 'production']), channel: z.enum(['test', 'stable']), issuedAt: utc, expiresAt: utc, releaseSequence: z.number().int().positive().safe(), artifacts: z.array(ArtifactSchema).max(32), withdrawnIds: z.array(z.string().max(160)).max(1024) }).strict();
export type ReleaseIndex = z.infer<typeof ReleaseSchema>;
export function verifyRelease(raw: string, build: BuildConfig, current: Watermark | null, now: number) {
  try {
    const verified = verifyEnvelope(raw, build.updateKeys, 'v2board-client-release-v1'); const index = ReleaseSchema.parse(verified.payload);
    assert(index.productId === build.productId && index.environment === build.environment && index.channel === build.channel);
    assert(Date.parse(index.issuedAt) <= now + 120000 && Date.parse(index.expiresAt) > now && Date.parse(index.expiresAt) > Date.parse(index.issuedAt));
    assert(new Set(index.artifacts.map(a => a.id)).size === index.artifacts.length);
    index.artifacts.forEach(a => { trustedUrl(a.url, build.trustedUpdateOrigins); assert(!(a.platform === 'win32' && (a.arch !== 'x64' || a.format !== 'nsis')) && !(a.platform === 'linux' && (a.arch !== 'x64' || a.format !== 'deb')) && !(a.platform === 'darwin' && !['dmg', 'zip'].includes(a.format))); });
    const watermark = { version: index.releaseSequence, hash: verified.hash }; const unchanged = checkWatermark(current, watermark);
    return { index, watermark, unchanged };
  } catch { throw new AppError('UPDATE_VERIFY_FAILED'); }
}
export function selectUpdate(index: ReleaseIndex, target: { platform: string; arch: string; version: string; osCompatible: (minimum: string) => boolean }) {
  return index.artifacts.filter(a => a.platform === target.platform && a.arch === target.arch && (a.platform !== 'darwin' || a.format === 'zip') && !index.withdrawnIds.includes(a.id) && gt(a.version, target.version) && target.osCompatible(a.minimumOS)).sort((a, b) => gt(a.version, b.version) ? -1 : 1)[0] ?? null;
}
export function osVersionAtLeast(actual: string, minimum: string) {
  if (![actual, minimum].every(value => /^\d+(?:\.\d+){0,3}$/.test(value))) return false;
  const a = actual.split('.').map(Number), b = minimum.split('.').map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) { if ((a[i] ?? 0) > (b[i] ?? 0)) return true; if ((a[i] ?? 0) < (b[i] ?? 0)) return false; }
  return true;
}
export function automaticDownloadAllowed(metered: boolean | null, battery: { percent: number; charging: boolean } | null) {
  return metered === false && battery !== null && (battery.charging || battery.percent >= 20);
}
export function requiredDiskBytes(artifact: Artifact) { return artifact.bytes + artifact.unpackedBytes + artifact.backupBytes + 300 * 1024 * 1024; }
export async function verifyArtifact(path: string, artifact: Artifact) {
  const hash = createHash('sha256'); let length = 0;
  for await (const chunk of createReadStream(path)) { length += (chunk as Buffer).length; if (length > artifact.bytes) throw new AppError('UPDATE_VERIFY_FAILED'); hash.update(chunk); }
  assert(length === artifact.bytes && hash.digest('hex') === artifact.sha256, 'UPDATE_VERIFY_FAILED');
}
export function installationGate(artifact: Artifact, index: ReleaseIndex, now: number, networkClean: boolean) {
  assert(Date.parse(index.expiresAt) > now && !index.withdrawnIds.includes(artifact.id) && index.artifacts.some(a => a.id === artifact.id && a.sha256 === artifact.sha256), 'UPDATE_VERIFY_FAILED');
  assert(networkClean, 'NETWORK_RECOVERY_REQUIRED');
}
