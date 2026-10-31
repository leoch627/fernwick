import { z } from 'zod';
import { isIP } from 'node:net';
import type { ProxyNode } from './model';
import { assert } from '../shared/errors';
import { defaultTlsProfile } from './tls-defaults';
const domain = z.string().min(1).max(253).refine(value => value.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)));
const ip = z.string().max(64).refine(value => {
  const parts = value.split('/'); if (parts.length > 2) return false;
  const family = isIP(parts[0]!); if (!family) return false;
  return parts.length === 1 || /^(0|[1-9][0-9]{0,2})$/.test(parts[1]!) && Number(parts[1]) <= (family === 4 ? 32 : 128);
});
export const RulesSchema = z.object({
  schemaVersion: z.literal(1), directDomains: z.array(domain).max(200000), directFullDomains: z.array(domain).max(200000).optional(), proxyDomains: z.array(domain).max(100000), blockedDomains: z.array(domain).max(100000), directIPs: z.array(ip).max(100000),
}).strict();
export type Rules = z.infer<typeof RulesSchema>;
export interface DnsTemplate { bootstrap: string; proxy: string; }
export const lanCIDRs = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10'];
export function compileOutbound(node: ProxyNode) {
  assert(node.compatible && node.tcp && node.udp, 'NO_COMPATIBLE_NODES');
  const streamSettings: Record<string, unknown> = { network: node.transport, security: node.security };
  if (node.security === 'tls') streamSettings.tlsSettings = { serverName: node.sni, allowInsecure: false, fingerprint: node.fingerprint ?? defaultTlsProfile.fingerprint };
  if (node.security === 'reality') streamSettings.realitySettings = { serverName: node.sni, fingerprint: node.fingerprint ?? defaultTlsProfile.fingerprint, publicKey: node.publicKey, shortId: node.shortId };
  if (node.transport === 'ws') streamSettings.wsSettings = { path: node.wsPath, headers: { Host: node.wsHost } };
  let settings: unknown;
  if (node.protocol === 'vless' || node.protocol === 'vmess') settings = { vnext: [{ address: node.host, port: node.port, users: [{ id: node.credential, ...(node.protocol === 'vless' ? { encryption: 'none', flow: node.flow ?? '' } : { alterId: 0, security: node.method ?? 'auto' }) }] }] };
  else settings = { servers: [{ address: node.host, port: node.port, password: node.credential, ...(node.protocol === 'shadowsocks' ? { method: node.method } : {}) }] };
  return { tag: 'proxy', protocol: node.protocol, settings, streamSettings };
}
export function compileRouting(mode: 'rule' | 'global', rules: Rules) {
  RulesSchema.parse(rules); const output: Record<string, unknown>[] = [
    { type: 'field', inboundTag: ['health'], outboundTag: 'proxy' },
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' },
    ...(rules.blockedDomains.length ? [{ type: 'field', domain: rules.blockedDomains.map(x => `domain:${x}`), outboundTag: 'block' }] : []),
    { type: 'field', ip: lanCIDRs, outboundTag: 'direct' },
  ];
  if (mode === 'rule') {
    if (rules.proxyDomains.length) output.push({ type: 'field', domain: rules.proxyDomains.map(x => `domain:${x}`), outboundTag: 'proxy' });
    if (rules.directDomains.length) output.push({ type: 'field', domain: rules.directDomains.map(x => `domain:${x}`), outboundTag: 'direct' });
    if (rules.directFullDomains?.length) output.push({ type: 'field', domain: rules.directFullDomains.map(x => `full:${x}`), outboundTag: 'direct' });
    if (rules.directIPs.length) output.push({ type: 'field', ip: rules.directIPs, outboundTag: 'direct' });
  }
  output.push({ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' }); return { domainStrategy: 'AsIs', rules: output };
}
/** Outbound/routing compiler only. TUN/DNS/physical binding must be supplied by a verified platform driver. */
export function compileCandidate(node: ProxyNode, mode: 'rule' | 'global', rules: Rules) {
  return { log: { loglevel: 'warning', access: 'none' }, outbounds: [compileOutbound(node), { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }], routing: compileRouting(mode, rules) };
}
