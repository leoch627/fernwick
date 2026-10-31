import { z } from 'zod';
import { AccountSchema } from '../shared/schema';
import { messages } from '../shared/errors';
const NodeSchema = z.object({
  id: z.string().regex(/^[a-f0-9]{64}$/), name: z.string().max(256), group: z.string().max(256), region: z.string().nullable(), order: z.number().int(),
  protocol: z.enum(['vless', 'vmess', 'trojan', 'shadowsocks', 'unsupported']), host: z.string().max(253), port: z.number().int().min(0).max(65535), credential: z.string().max(2048), method: z.string().optional(), transport: z.enum(['tcp', 'ws']), security: z.enum(['tls', 'reality', 'none']),
  sni: z.string().optional(), flow: z.string().optional(), publicKey: z.string().optional(), shortId: z.string().optional(), fingerprint: z.string().optional(), wsPath: z.string().optional(), wsHost: z.string().optional(),
  compatible: z.boolean(), incompatibility: z.string().nullable(), tcp: z.boolean(), udp: z.boolean(), ipv6: z.enum(['unknown', 'verified']), connectionFingerprint: z.string().regex(/^[a-f0-9]{64}$/), source: z.string(),
}).strict();
export const SnapshotSchema = z.object({
  productId: z.string(), environment: z.string(), adapterId: z.string(), accountId: z.string(), sessionGeneration: z.string(), opSeq: z.number().int(), account: AccountSchema, nodes: z.array(NodeSchema).max(5000),
  fullSyncCompletedAt: z.number().safe(), usableUntil: z.number().safe(), maxAgeAtCommitSec: z.number().int().min(600).max(86400), quarantinedNodeCount: z.number().int().nonnegative(), authoritativeEmpty: z.boolean(), contentHash: z.string().regex(/^[a-f0-9]{64}$/),
}).strict().refine(s => s.usableUntil <= s.fullSyncCompletedAt + s.maxAgeAtCommitSec * 1000);
export const PersistedSchema = z.object({
  schemaVersion: z.literal(1), productId: z.string(), environment: z.string(),
  session: z.object({ accountId: z.string().min(1), email: z.string().email(), token: z.string().max(8192), generation: z.string().min(1) }).strict(),
  snapshot: SnapshotSchema.nullable(), account: AccountSchema.nullable(),
  restrictions: z.array(z.enum(Object.keys(messages) as [keyof typeof messages, ...(keyof typeof messages)[]])), timeUpper: z.number().safe(),
}).strict();
export type Persisted = z.infer<typeof PersistedSchema>;
