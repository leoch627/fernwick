import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { AccountSchema, type Account, type BuildConfig } from '../shared/schema';
import type { Session, SubscriptionDescriptor } from '../domain/model';
import { Budget } from '../domain/time';
import { AppError, assert } from '../shared/errors';
import { strictJson } from '../domain/json';
import { trustedUrl } from '../domain/trust';
import { requireSuccess, type Transport } from './http';
export interface PanelAdapter {
  login(endpoint: string, email: string, password: string, budget: Budget): Promise<Session>;
  fetchAccount(endpoint: string, session: Session, budget: Budget): Promise<Account>;
  fetchSubscriptionDescriptor(endpoint: string, session: Session, budget: Budget): Promise<SubscriptionDescriptor>;
  fetchNodes(descriptor: SubscriptionDescriptor, budget: Budget): Promise<string>;
  logout?(endpoint: string, session: Session, budget: Budget): Promise<void>;
}
const apiPath = z.string().regex(/^\/api\/[a-zA-Z0-9/_-]+$/);
export const ContractSchema = z.object({
  verified: z.boolean(), deployment: z.string(), branchCommit: z.string(),
  loginPath: z.string().regex(/^\/api\/[a-zA-Z0-9/_-]+$/), accountPath: z.string().regex(/^\/api\/[a-zA-Z0-9/_-]+$/), descriptorPath: z.string().regex(/^\/api\/[a-zA-Z0-9/_-]+$/),
  authPrefix: z.enum(['', 'Bearer ']), expiryUnit: z.literal('seconds'),
  logoutPath: z.string().regex(/^\/api\/[a-zA-Z0-9/_-]+$/).nullable().default(null),
  passport: z.object({ configPath: apiPath, emailCodePath: apiPath, registerPath: apiPath, resetPath: apiPath, quickLoginPath: apiPath, inviteFetchPath: apiPath, inviteCreatePath: apiPath }).strict().nullable().default(null),
  activePlanAuthorizesService: z.boolean(), nullExpiryIsUnlimited: z.boolean(), zeroQuotaIsUnlimited: z.boolean(),
  fields: z.object({ accountId: z.string(), email: z.string(), banned: z.string(), planId: z.string(), expires: z.string(), quota: z.string(), upload: z.string(), download: z.string(), subscriptionUrl: z.string() }).strict(),
}).strict();
export type PanelContract = z.infer<typeof ContractSchema>;
const bytes = (value: unknown): bigint | null => {
  if (typeof value === 'string' && /^(0|[1-9]\d{0,29})$/.test(value)) return BigInt(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value); return null;
};
export function normalizeAccount(data: Record<string, unknown>, contract: PanelContract, session: Session, endpoint: string, now = Date.now()): Account {
  const f = contract.fields; const id = data[f.accountId]; const email = data[f.email];
  assert(String(id) === session.accountId && typeof email === 'string' && email.toLowerCase() === session.email.toLowerCase(), 'CONTROL_UNAVAILABLE');
  const rawBanned = data[f.banned]; const banned = rawBanned === 1 || rawBanned === true ? 'yes' : rawBanned === 0 || rawBanned === false ? 'no' : 'unknown';
  const rawPlan = data[f.planId]; const hasPlan = rawPlan === null || rawPlan === 0 ? 'no' : typeof rawPlan === 'number' && Number.isSafeInteger(rawPlan) && rawPlan > 0 ? 'yes' : 'unknown';
  const expiry = data[f.expires];
  const finite = typeof expiry === 'number' && Number.isSafeInteger(expiry) && expiry > 0 && expiry < 253402300800;
  const expiryKind = finite ? 'finite' : expiry === null && contract.nullExpiryIsUnlimited ? 'unlimited' : 'unknown';
  const quota = bytes(data[f.quota]), up = bytes(data[f.upload]), down = bytes(data[f.download]);
  const used = up !== null && down !== null ? up + down : null;
  const quotaKind = quota === 0n && contract.zeroQuotaIsUnlimited ? 'unlimited' : quota !== null ? 'finite' : 'unknown';
  const trafficExhausted = quotaKind === 'finite' && used !== null ? used >= quota! ? 'yes' : 'no' : quotaKind === 'unlimited' ? 'no' : 'unknown';
  const expiryEvidence = finite || expiry === null && contract.nullExpiryIsUnlimited;
  const serviceAllowed = banned === 'yes' || hasPlan === 'no' || expiry === 0 ? 'no' : contract.activePlanAuthorizesService && banned === 'no' && hasPlan === 'yes' && trafficExhausted === 'no' && expiryEvidence ? 'yes' : 'unknown';
  return AccountSchema.parse({ accountId: session.accountId, email, planName: typeof (data.plan as { name?: unknown })?.name === 'string' ? (data.plan as { name: string }).name : '当前套餐', sessionStatus: 'valid', serviceAllowed, banned, hasPlan, trafficExhausted, expiryKind, expiresAt: finite ? new Date(expiry * 1000).toISOString() : null, quotaKind, usedBytes: used?.toString() ?? null, quotaBytes: quotaKind === 'finite' ? quota!.toString() : null, resetAt: null, observedAt: new Date(now).toISOString(), sourceEndpointId: endpoint, authorizationEvidence: serviceAllowed === 'yes' ? `deployment-contract:${contract.branchCommit}:active-plan-and-quota` : '' });
}
export class V2BoardAdapter implements PanelAdapter {
  constructor(private build: BuildConfig, private contract: PanelContract, private http: Transport) {}
  private url(endpoint: string, path: string) {
    assert(this.contract.verified, 'CONFIGURATION_REQUIRED');
    const entry = this.build.apiEndpoints.find(e => e.id === endpoint); assert(entry, 'CONFIGURATION_REQUIRED');
    return entry.baseUrl.replace(/\/$/, '') + path;
  }
  private data(body: string) {
    const response = strictJson(body) as { data?: unknown }; assert(response && typeof response === 'object' && response.data && typeof response.data === 'object' && !Array.isArray(response.data), 'CONTROL_UNAVAILABLE');
    return response.data as Record<string, unknown>;
  }
  async login(endpoint: string, email: string, password: string, budget: Budget): Promise<Session> {
    const response = await this.http.request({ url: this.url(endpoint, this.contract.loginPath), method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) }, budget);
    // This branch also returns 500 for wrong credentials and password throttling. Never retry login automatically.
    if (response.status === 500) throw new AppError('LOGIN_FAILED');
    requireSuccess(response, 'login'); const data = this.data(response.body);
    assert(typeof data.auth_data === 'string' && data.auth_data.length <= 8192 && !/[\r\n]/.test(data.auth_data), 'LOGIN_FAILED');
    const temporary = { accountId: '', email, token: data.auth_data, generation: randomUUID() };
    // Identity is obtained with the new session; login is never replayed across endpoints.
    const identity = await this.readAccount(endpoint, temporary, budget); const id = identity[this.contract.fields.accountId];
    assert((typeof id === 'string' && id.length > 0) || (typeof id === 'number' && Number.isSafeInteger(id)), 'CONTROL_UNAVAILABLE');
    temporary.accountId = String(id); normalizeAccount(identity, this.contract, temporary, endpoint); return temporary;
  }
  private async readAccount(endpoint: string, session: Session, budget: Budget) {
    const response = await this.http.request({ url: this.url(endpoint, this.contract.accountPath), headers: { authorization: this.contract.authPrefix + session.token } }, budget);
    requireSuccess(response, 'account'); return this.data(response.body);
  }
  async fetchAccount(endpoint: string, session: Session, budget: Budget) {
    const info = await this.readAccount(endpoint, session, budget);
    if (info[this.contract.fields.banned] === 1 || info[this.contract.fields.banned] === true) return normalizeAccount(info, this.contract, session, endpoint);
    const response = await this.http.request({ url: this.url(endpoint, this.contract.descriptorPath), headers: { authorization: this.contract.authPrefix + session.token } }, budget);
    requireSuccess(response, 'account'); const subscription = this.data(response.body); const f = this.contract.fields;
    assert(String(info[f.accountId]) === String(subscription[f.accountId]) && info[f.email] === subscription[f.email], 'CONTROL_UNAVAILABLE');
    // Identity, ban, expiry and plan are read from user/info; usage/plan display from getSubscribe.
    assert(info[f.expires] === subscription[f.expires] && info[f.planId] === subscription[f.planId] && String(info[f.quota]) === String(subscription[f.quota]), 'CONTROL_UNAVAILABLE');
    return normalizeAccount({ ...subscription, ...info }, this.contract, session, endpoint);
  }
  async fetchSubscriptionDescriptor(endpoint: string, session: Session, budget: Budget): Promise<SubscriptionDescriptor> {
    const response = await this.http.request({ url: this.url(endpoint, this.contract.descriptorPath), headers: { authorization: this.contract.authPrefix + session.token } }, budget);
    requireSuccess(response, 'account'); const data = this.data(response.body); const url = data[this.contract.fields.subscriptionUrl];
    assert(typeof url === 'string' && url.length <= 8192, 'SUBSCRIPTION_INVALID');
    const selected = new URL(trustedUrl(url, this.build.trustedSubscriptionOrigins));
    // Frozen fork contract: an explicit empty flag uses General and bypasses display pseudo-nodes.
    selected.searchParams.set('flag', '');
    return { url: selected.href, format: 'v2ray-uri-base64-v1', authoritativeEmpty: false };
  }
  async fetchNodes(descriptor: SubscriptionDescriptor, budget: Budget) {
    const response = await this.http.request({ url: trustedUrl(descriptor.url, this.build.trustedSubscriptionOrigins), maxBytes: 14 * 1024 * 1024 }, budget);
    requireSuccess(response, 'subscription'); return response.body;
  }
  async logout(endpoint: string, session: Session, budget: Budget) {
    if (!this.contract.logoutPath) return;
    // This claim only selects the current server session for removal; it never authorizes access.
    const parts = session.token.split('.'); assert(parts.length === 3, 'CONTROL_UNAVAILABLE');
    const claim = strictJson(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as { session?: unknown };
    assert(typeof claim.session === 'string' && /^[a-zA-Z0-9-]{1,128}$/.test(claim.session), 'CONTROL_UNAVAILABLE');
    const response = await this.http.request({ url: this.url(endpoint, this.contract.logoutPath), method: 'POST', headers: { authorization: this.contract.authPrefix + session.token, 'content-type': 'application/json' }, body: JSON.stringify({ session_id: claim.session }) }, budget);
    requireSuccess(response, 'account'); assert((strictJson(response.body) as { data?: unknown }).data === true, 'CONTROL_UNAVAILABLE');
  }
}
