import type { Account } from '../shared/schema';
export type Protocol = 'vless' | 'vmess' | 'trojan' | 'shadowsocks';
export interface ProxyNode {
  id: string; name: string; group: string; region: string | null; order: number;
  protocol: Protocol | 'unsupported'; host: string; port: number;
  credential: string; method?: string; transport: 'tcp' | 'ws'; security: 'tls' | 'reality' | 'none';
  sni?: string; flow?: string; publicKey?: string; shortId?: string; fingerprint?: string; wsPath?: string; wsHost?: string;
  compatible: boolean; incompatibility: string | null; tcp: boolean; udp: boolean; ipv6: 'unknown' | 'verified';
  connectionFingerprint: string; source: string;
}
export interface Session { accountId: string; email: string; token: string; generation: string; }
export interface Snapshot {
  productId: string; environment: string; adapterId: string; accountId: string; sessionGeneration: string;
  opSeq: number; account: Account; nodes: ProxyNode[]; fullSyncCompletedAt: number; usableUntil: number;
  maxAgeAtCommitSec: number; quarantinedNodeCount: number; authoritativeEmpty: boolean; contentHash: string;
}
export interface ParsedNodes { nodes: ProxyNode[]; quarantined: { index: number; reason: string }[]; authoritativeEmpty: boolean; }
export interface SubscriptionDescriptor { url: string; format: 'v2ray-uri-base64-v1'; authoritativeEmpty: boolean; }
