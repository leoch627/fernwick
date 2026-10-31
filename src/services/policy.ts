import { createHash, verify } from 'node:crypto';
import { z } from 'zod';
import { PolicySchema, type Policy, type BuildConfig } from '../shared/schema';
import { assert, AppError } from '../shared/errors';
import { strictJson } from '../domain/json';
import { trustedUrl } from '../domain/trust';
import { decodeBase64 } from '../domain/subscription';
export const EnvelopeSchema = z.object({ keyId: z.string().min(1).max(128), payload: z.string().regex(/^[A-Za-z0-9_-]+$/), signature: z.string().regex(/^[A-Za-z0-9_-]+$/) }).strict();
export interface Watermark { version: number; hash: string; }
export function verifyEnvelope(raw: string, keys: Record<string, string>, purpose: string) {
  try {
    const envelope = EnvelopeSchema.parse(strictJson(raw)); const key = keys[envelope.keyId]; assert(key, 'POLICY_INVALID');
    const bytes = decodeBase64(envelope.payload), signature = decodeBase64(envelope.signature);
    assert(signature.length === 64 && verify(null, Buffer.concat([Buffer.from(purpose + '\n'), bytes]), key, signature), 'POLICY_INVALID');
    const payload = strictJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return { payload, hash: createHash('sha256').update(bytes).digest('hex') };
  } catch { throw new AppError('POLICY_INVALID'); }
}
export function checkWatermark(current: Watermark | null, next: Watermark) {
  assert(!current || next.version > current.version || next.version === current.version && next.hash === current.hash, 'POLICY_INVALID');
  return current?.version === next.version;
}
export function verifyPolicy(raw: string, build: BuildConfig, watermark: Watermark | null, now: number) {
  try {
    const signed = verifyEnvelope(raw, build.policyKeys, 'v2board-client-policy-v1'); const policy = PolicySchema.parse(signed.payload);
    assert(policy.productId === build.productId && policy.environment === build.environment && policy.channel === build.channel, 'POLICY_INVALID');
    const issued = Date.parse(policy.issuedAt), from = Date.parse(policy.notBefore), until = Date.parse(policy.expiresAt);
    assert(issued <= now + 120000 && from <= now && until > now && issued <= from && from < until, 'POLICY_INVALID');
    const ids = new Set(build.apiEndpoints.map(e => e.id)); const { orderedIds, temporarilyDisabledIds } = policy.endpoints;
    assert(orderedIds.length === ids.size && new Set(orderedIds).size === ids.size && orderedIds.every(id => ids.has(id)) && temporarilyDisabledIds.every(id => ids.has(id)) && new Set(temporarilyDisabledIds).size === temporarilyDisabledIds.length, 'POLICY_INVALID');
    assert(orderedIds.some(id => !temporarilyDisabledIds.includes(id)), 'POLICY_INVALID');
    Object.values(policy.links).forEach(url => trustedUrl(url, build.trustedWebOrigins));
    if (policy.routing.resource) { trustedUrl(policy.routing.resource.url, build.trustedResourceOrigins); assert(Date.parse(policy.routing.resource.expiresAt) <= until && Date.parse(policy.routing.resource.expiresAt) > now, 'POLICY_INVALID'); }
    if (policy.maintenance) { const a = Date.parse(policy.maintenance.startsAt), b = Date.parse(policy.maintenance.endsAt); assert(a < b && b - a <= 86400000 && b <= until && a >= from, 'POLICY_INVALID'); }
    assert(new Set(policy.nodeOperations.map(n => n.nodeId)).size === policy.nodeOperations.length, 'POLICY_INVALID');
    const next = { version: policy.policyVersion, hash: signed.hash }; return { policy, watermark: next, unchanged: checkWatermark(watermark, next) };
  } catch { throw new AppError('POLICY_INVALID'); }
}
export interface PolicyRecord { envelope: string; watermark: Watermark; }
export class PolicyService {
  private record: PolicyRecord | null = null; private policy: Policy | null = null; private queue: Promise<unknown> = Promise.resolve(); generation = 0;
  constructor(private build: BuildConfig, private persist: (record: PolicyRecord) => Promise<void>, private now = () => Date.now()) {}
  restore(record: PolicyRecord) {
    // Validate the signed historical content at notBefore before trusting the persisted high water.
    const signed = verifyEnvelope(record.envelope, this.build.policyKeys, 'v2board-client-policy-v1'); const historical = PolicySchema.parse(signed.payload);
    const checked = verifyPolicy(record.envelope, this.build, null, Date.parse(historical.notBefore));
    assert(checked.watermark.version === record.watermark.version && checked.watermark.hash === record.watermark.hash, 'POLICY_INVALID');
    this.record = record; this.policy = checked.policy;
  }
  get active(): Policy | null { return this.policy && Date.parse(this.policy.notBefore) <= this.now() && Date.parse(this.policy.expiresAt) > this.now() ? this.policy : null; }
  get watermark() { return this.record?.watermark ?? null; }
  get envelope() { return this.record?.envelope ?? null; }
  accept(envelope: string): Promise<boolean> {
    const op = this.queue.then(async () => { const checked = verifyPolicy(envelope, this.build, this.watermark, this.now()); if (checked.unchanged) return false;
      const record = { envelope, watermark: checked.watermark }; await this.persist(record);
      this.record = record; this.policy = checked.policy; this.generation++; return true;
    }); this.queue = op.catch(() => {}); return op;
  }
}
