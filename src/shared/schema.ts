import { z } from 'zod';
const text = z.string().min(1).max(256);
export const utc = z.string().datetime({ offset: true });
export const decimal = z.string().regex(/^(0|[1-9][0-9]{0,29})$/);
const tri = z.enum(['yes', 'no', 'unknown']);
export const AccountSchema = z.object({
  accountId: text, email: z.string().email().max(254), planName: z.string().max(256),
  sessionStatus: z.enum(['valid', 'invalid', 'unknown']), serviceAllowed: tri,
  banned: tri, hasPlan: tri, trafficExhausted: tri,
  expiryKind: z.enum(['finite', 'unlimited', 'unknown']), expiresAt: utc.nullable(),
  quotaKind: z.enum(['finite', 'unlimited', 'unknown']), usedBytes: decimal.nullable(), quotaBytes: decimal.nullable(),
  resetAt: utc.nullable(), observedAt: utc, sourceEndpointId: text, authorizationEvidence: z.string().max(512),
}).strict().superRefine((a, ctx) => {
  if ((a.expiryKind === 'finite') !== (a.expiresAt !== null)) ctx.addIssue({ code: 'custom', message: 'expiry kind/date mismatch' });
  if (a.quotaKind === 'finite' && a.quotaBytes === null) ctx.addIssue({ code: 'custom', message: 'missing quota' });
  if (a.serviceAllowed === 'yes' && !a.authorizationEvidence) ctx.addIssue({ code: 'custom', message: 'missing authorization evidence' });
});
export type Account = z.infer<typeof AccountSchema>;
export const RefreshSchema = z.object({
  subscriptionIntervalSec: z.number().int().min(300).max(21600),
  accountIntervalSec: z.number().int().min(60).max(3600),
  policyIntervalSec: z.number().int().min(300).max(3600),
  maxSnapshotAgeSec: z.number().int().min(600).max(604800),
}).strict().superRefine((r, ctx) => {
  if (r.accountIntervalSec > r.subscriptionIntervalSec || r.subscriptionIntervalSec * 1.1 + 80 >= r.maxSnapshotAgeSec)
    ctx.addIssue({ code: 'custom', message: 'refresh intervals exceed authorization window' });
});
export const defaults = { subscriptionIntervalSec: 1800, accountIntervalSec: 300, policyIntervalSec: 900, maxSnapshotAgeSec: 604800 } as const;
export const BuildSchema = z.object({
  schemaVersion: z.literal(2), productId: text, appId: text, name: text,
  environment: z.enum(['test', 'production']), channel: z.enum(['test', 'stable']), tenantId: text,
  adapterId: z.literal('v2board-explicit-v1'), deploymentVerified: z.boolean(), subscriptionFormatId: z.literal('v2ray-uri-base64-v1'),
  apiEndpoints: z.array(z.object({ id: text, baseUrl: z.string().url(), priority: z.number().int() }).strict()).max(8),
  trustedSubscriptionOrigins: z.array(z.string().url()).max(16), trustedWebOrigins: z.array(z.string().url()).max(16),
  trustedResourceOrigins: z.array(z.string().url()).max(16), policyUrls: z.array(z.string().url()).max(8), updateFeedUrls: z.array(z.string().url()).max(8),
  trustedUpdateOrigins: z.array(z.string().url()).max(16),
  links: z.object({ website: z.string().url().nullable(), renew: z.string().url().nullable(), help: z.string().url().nullable() }).strict(),
  policyKeys: z.record(z.string(), z.string().max(2048)), updateKeys: z.record(z.string(), z.string().max(2048)),
  protocolCapabilities: z.array(z.enum(['vless-tls', 'vless-reality', 'vmess-ws-tls', 'trojan-tls', 'shadowsocks-aead'])),
  nodeCapabilitiesConfirmed: z.boolean(),
  allowUnverifiedNodeTrials: z.boolean().default(false),
  healthTargets: z.array(z.object({ url: z.string().url(), status: z.number().int().min(200).max(299), bodySha256: z.string().regex(/^[a-f0-9]{64}$/), failureDomain: text }).strict()).max(3).default([]),
  hardLimits: z.object({ startupNetworkBudgetSec: z.literal(20), networkTransactionSec: z.literal(15), maxSnapshotAgeSec: z.literal(604800), subscriptionDecodedMaxBytes: z.literal(10485760), subscriptionMaxNodes: z.literal(5000) }).strict(),
}).strict();
export type BuildConfig = z.infer<typeof BuildSchema>;
export const NodeOperationSchema = z.object({ nodeId: text, hiddenFromList: z.boolean(), eligibleForAuto: z.boolean(), disabledForConnection: z.boolean(), order: z.number().int().optional(), group: text.optional() }).strict();
export const ResourceSchema = z.object({ id: text, version: z.number().int().positive().safe(), url: z.string().url(), sha256: z.string().regex(/^[a-f0-9]{64}$/), bytes: z.number().int().min(1).max(33554432), expiresAt: utc }).strict();
export const PolicySchema = z.object({
  schemaVersion: z.literal(2), policyVersion: z.number().int().positive().safe(), productId: text,
  environment: z.enum(['test', 'production']), channel: z.enum(['test', 'stable']),
  issuedAt: utc, notBefore: utc, expiresAt: utc, requiredCapabilities: z.array(z.enum(['tun', 'policy-schema-2'])).max(10),
  endpoints: z.object({ orderedIds: z.array(text).min(1).max(8), temporarilyDisabledIds: z.array(text).max(8) }).strict(),
  refresh: RefreshSchema,
  ui: z.object({ expiryReminderDays: z.array(z.number().int().min(1).max(30)).max(5), showTrafficSummary: z.boolean(), announcement: z.object({ id: text, text: z.string().max(2000) }).strict().nullable() }).strict(),
  links: z.object({ website: z.string().url(), renew: z.string().url(), help: z.string().url() }).strict(),
  nodeOperations: z.array(NodeOperationSchema).max(5000),
  routing: z.object({ templateId: z.literal('cn-direct-default-proxy-v1'), dnsTemplateId: z.literal('real-dns-split-v1'), resource: ResourceSchema.nullable() }).strict(),
  maintenance: z.object({ reason: z.string().min(1).max(500), startsAt: utc, endsAt: utc, platforms: z.array(z.enum(['win32', 'darwin', 'linux'])).min(1) }).strict().nullable(),
  update: z.object({ checkIntervalSec: z.number().int().min(3600).max(86400), noticeText: z.string().max(1000).nullable() }).strict(),
}).strict();
export type Policy = z.infer<typeof PolicySchema>;
export const PreferencesSchema = z.object({
  mode: z.enum(['rule', 'global']), nodeId: text.nullable(), autoConnect: z.boolean(), launchAtLogin: z.boolean(),
  closeBehavior: z.enum(['tray', 'ask']), theme: z.enum(['light', 'dark', 'system']),
  // Older preference files have neither field and load with these defaults.
  tunnel: z.enum(['proxy', 'tun']).default('proxy'), adBlock: z.boolean().default(true),
}).strict();
export type Preferences = z.infer<typeof PreferencesSchema>;
export const defaultPreferences: Preferences = { mode: 'rule', nodeId: null, autoConnect: false, launchAtLogin: false, closeBehavior: 'tray', theme: 'system', tunnel: 'proxy', adBlock: true };
export const CommandSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('login'), email: z.string().email().max(254), password: z.string().min(1).max(1024) }).strict(),
  ...(['state', 'sync', 'connect', 'disconnect', 'logout', 'repair', 'check-update', 'download-update', 'pause-update', 'cancel-update', 'install-update', 'diagnostics', 'renewal-return'] as const).map(type => z.object({ type: z.literal(type) }).strict()),
  z.object({ type: z.literal('preferences'), preferences: PreferencesSchema }).strict(),
  z.object({ type: z.literal('probe-nodes'), nodeIds: z.array(text).min(1).max(64) }).strict(),
  z.object({ type: z.literal('report'), note: z.string().max(500) }).strict(),
  z.object({ type: z.literal('open-link'), link: z.enum(['website', 'renew', 'help']) }).strict(),
]);
export type Command = z.infer<typeof CommandSchema>;
