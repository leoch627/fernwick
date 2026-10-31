import { createHash } from 'node:crypto';
import { z } from 'zod';
import { ResourceSchema, type BuildConfig } from '../shared/schema';
import { RulesSchema, type Rules } from '../domain/compiler';
import { strictJson } from '../domain/json';
import { trustedUrl } from '../domain/trust';
import { assert } from '../shared/errors';
export type RuleResource = z.infer<typeof ResourceSchema>;
export function validateResource(bytes: Buffer, descriptor: RuleResource, build: BuildConfig, now: number): Rules {
  trustedUrl(descriptor.url, build.trustedResourceOrigins);
  assert(descriptor.bytes === bytes.length && bytes.length <= 33554432 && Date.parse(descriptor.expiresAt) > now, 'POLICY_INVALID');
  assert(createHash('sha256').update(bytes).digest('hex') === descriptor.sha256, 'POLICY_INVALID');
  return RulesSchema.parse(strictJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes), 33554432));
}
export class RoutingResources {
  active: { descriptor: RuleResource; rules: Rules } | null = null;
  pending: string | null = null;
  private identities = new Map<string, string>();
  constructor(private build: BuildConfig, private persist: (resource: { descriptor: RuleResource; rules: Rules }) => Promise<void>) {}
  async activate(bytes: Buffer, descriptor: RuleResource, now: number) {
    const rules = validateResource(bytes, descriptor, this.build, now); const prior = this.identities.get(descriptor.id);
    assert(!prior || prior === descriptor.sha256, 'POLICY_INVALID');
    assert(!this.active || descriptor.version >= this.active.descriptor.version, 'POLICY_INVALID');
    const next = { descriptor, rules }; await this.persist(next); this.active = next; this.identities.set(descriptor.id, descriptor.sha256); this.pending = null;
  }
  current(now: number, baseline: Rules) { return this.active && Date.parse(this.active.descriptor.expiresAt) > now ? this.active.rules : baseline; }
}
