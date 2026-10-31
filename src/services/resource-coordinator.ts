import { createHash } from 'node:crypto';
import { z } from 'zod';
import { PolicySchema, type BuildConfig } from '../shared/schema';
import { Budget } from '../domain/time';
import { RulesSchema, type Rules } from '../domain/compiler';
import { verifyEnvelope, verifyPolicy } from './policy';
import { validateResource, type RuleResource } from './resources';
import { requireSuccess, type Transport } from './http';
import type { JsonStore } from './storage';
import { AppError, assert } from '../shared/errors';
const IdentitySchema = z.object({ id: z.string().max(160), sha256: z.string().regex(/^[a-f0-9]{64}$/), version: z.number().int().positive().safe() }).strict();
export const ResourceCacheSchema = z.object({ policyEnvelope: z.string().max(262144), body: z.string().max(33554432).nullable(), identities: z.array(IdentitySchema).max(4096).default([]) }).strict();
export type ResourceCache = z.infer<typeof ResourceCacheSchema>;
export class ResourceCoordinator {
  private active: { descriptor: RuleResource; rules: Rules } | null = null;
  private serial: Promise<void> = Promise.resolve(); private sequence = 0; private budget: Budget | null = null;
  private pending = false; private failed = false; private changed = () => {};
  private identities: ResourceCache['identities'] = [];
  private baselineHash: string;
  constructor(private build: BuildConfig, private baseline: Rules, private store: JsonStore<ResourceCache>, private http: Transport, private now = () => Date.now()) {
    RulesSchema.parse(baseline); this.baselineHash = createHash('sha256').update(JSON.stringify(baseline)).digest('hex');
  }
  onChange(listener: () => void) { this.changed = listener; }
  private get valid() { return this.active && Date.parse(this.active.descriptor.expiresAt) > this.now() ? this.active : null; }
  get rules() { return this.valid?.rules ?? this.baseline; }
  get fingerprint() { return this.valid?.descriptor.sha256 ?? this.baselineHash; }
  get status() { return this.pending ? '规则正在更新，继续使用当前规则' : this.failed ? '新规则未验证，保留有效规则或内置规则' : this.valid ? `规则已验证 v${this.valid.descriptor.version}` : '使用内置大陆分流规则'; }
  async restore() {
    try {
      const record = await this.store.load(); if (!record) return;
      const historical = PolicySchema.parse(verifyEnvelope(record.policyEnvelope, this.build.policyKeys, 'v2board-client-policy-v1').payload);
      const checked = verifyPolicy(record.policyEnvelope, this.build, null, Date.parse(historical.notBefore));
      const descriptor = checked.policy.routing.resource;
      const identities = record.identities ?? [];
      assert(new Set(identities.map(value => value.id)).size === identities.length, 'POLICY_INVALID');
      if (descriptor && record.body !== null) {
        const rules = validateResource(Buffer.from(record.body), descriptor, this.build, Date.parse(historical.notBefore));
        const prior = identities.find(value => value.id === descriptor.id);
        assert(!prior || prior.sha256 === descriptor.sha256, 'POLICY_INVALID');
        if (!prior) identities.push({ id: descriptor.id, sha256: descriptor.sha256, version: descriptor.version });
        if (Date.parse(descriptor.expiresAt) > this.now()) this.active = { descriptor, rules };
      }
      this.identities = identities;
    } catch { this.failed = true; }
  }
  apply(envelope: string) {
    this.budget?.cancel(); const sequence = ++this.sequence; this.pending = true; this.changed();
    const operation = this.serial.then(async () => {
      if (sequence !== this.sequence) return;
      const budget = new Budget(12000); this.budget = budget;
      const isCurrent = () => sequence === this.sequence && !budget.signal.aborted;
      const current = () => { if (!isCurrent()) throw new AppError('CANCELLED'); };
      try {
        const descriptor = verifyPolicy(envelope, this.build, null, this.now()).policy.routing.resource;
        if (!descriptor) { await this.store.save({ policyEnvelope: envelope, body: null, identities: this.identities }, isCurrent); current(); this.active = null; this.failed = false; return; }
        if (this.active && JSON.stringify(this.active.descriptor) === JSON.stringify(descriptor)) { this.failed = false; return; }
        const prior = this.identities.find(value => value.id === descriptor.id);
        const latest = this.identities.reduce<(typeof this.identities)[number] | null>((best, value) => !best || value.version > best.version ? value : best, null);
        assert(!prior || prior.sha256 === descriptor.sha256, 'POLICY_INVALID');
        assert(!latest || descriptor.version > latest.version || descriptor.version === latest.version && descriptor.sha256 === latest.sha256, 'POLICY_INVALID');
        assert(prior || this.identities.length < 4096, 'POLICY_INVALID');
        const response = await budget.run(() => this.http.request({ url: descriptor.url, maxBytes: descriptor.bytes }, budget)); requireSuccess(response, 'public'); current();
        const rules = validateResource(Buffer.from(response.body), descriptor, this.build, this.now());
        const identities = [...this.identities.filter(value => value.id !== descriptor.id), { id: descriptor.id, sha256: descriptor.sha256, version: descriptor.version }];
        await this.store.save({ policyEnvelope: envelope, body: response.body, identities }, isCurrent); current();
        // Commit independent routing state only after the exact hash-checked bytes are durable.
        this.active = { descriptor, rules }; this.identities = identities; this.failed = false;
      } catch { if (sequence === this.sequence) this.failed = true; }
      finally { budget.dispose(); if (sequence === this.sequence) { this.pending = false; this.budget = null; this.changed(); } }
    }); this.serial = operation.catch(() => {}); return operation;
  }
  async stop() { this.sequence++; this.budget?.cancel(); await this.serial; }
}
