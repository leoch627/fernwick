import { z } from 'zod';
import { isIP } from 'node:net';
import type { ProxyNode } from './model';
import { assert } from '../shared/errors';
import { modernFingerprint } from './tls-defaults';
const domain = z.string().min(1).max(253).refine(value => value.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)));
const ip = z.string().max(64).refine(value => {
  const parts = value.split('/'); if (parts.length > 2) return false;
  const family = isIP(parts[0]!); if (!family) return false;
  return parts.length === 1 || /^(0|[1-9][0-9]{0,2})$/.test(parts[1]!) && Number(parts[1]) <= (family === 4 ? 32 : 128);
});
/** Xray matcher forms used by the rule data; geosite:/ext: would make the core open files. */
const ruleDomain = z.string().max(520).refine(value => {
  const at = value.indexOf(':'); const kind = value.slice(0, at); const rest = value.slice(at + 1);
  if (at < 0) return false;
  if (kind === 'domain' || kind === 'full') return domain.safeParse(rest).success;
  if (kind === 'keyword') return /^[a-z0-9.-]{1,253}$/.test(rest);
  if (kind !== 'regexp' || !rest || rest.length > 512 || !/^[\x20-\x7e]+$/.test(rest) || /\(\?[=!<]|\\[1-9]/.test(rest)) return false;
  try { new RegExp(rest); return true; } catch { return false; }
});
const RuleSectionSchema = z.object({ target: z.enum(['direct', 'proxy', 'ai', 'block']), domains: z.array(ruleDomain).optional(), ips: z.array(ip).optional() }).strict();
export const RulesSchema = z.object({ schemaVersion: z.literal(2), sections: z.array(RuleSectionSchema).max(64) }).strict()
  .refine(rules => rules.sections.reduce((n, s) => n + (s.domains?.length ?? 0), 0) <= 200000 && rules.sections.reduce((n, s) => n + (s.ips?.length ?? 0), 0) <= 100000, 'Rule data exceeds client limits');
export type Rules = z.infer<typeof RulesSchema>;
export interface DnsTemplate { bootstrap: string; proxy: string; }
export const lanCIDRs = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10'];
export function compileOutbound(node: ProxyNode) {
  assert(node.compatible && node.tcp && node.udp, 'NO_COMPATIBLE_NODES');
  const streamSettings: Record<string, unknown> = { network: node.transport, security: node.security };
  if (node.security === 'tls') streamSettings.tlsSettings = { serverName: node.sni, allowInsecure: false, fingerprint: modernFingerprint(node.fingerprint) };
  if (node.security === 'reality') streamSettings.realitySettings = { serverName: node.sni, fingerprint: modernFingerprint(node.fingerprint), publicKey: node.publicKey, shortId: node.shortId };
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
    { type: 'field', ip: lanCIDRs, outboundTag: 'direct' },
  ];
  for (const section of rules.sections) {
    // Global mode still blocks ads; a single-node config has no separate AI exit.
    if (mode === 'global' && section.target !== 'block' && section.target !== 'ai') continue;
    const outboundTag = section.target === 'ai' ? 'proxy' : section.target;
    if (section.domains?.length) output.push({ type: 'field', domain: section.domains, outboundTag });
    if (section.ips?.length) output.push({ type: 'field', ip: section.ips, outboundTag });
  }
  output.push({ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' }); return { domainStrategy: 'AsIs', rules: output };
}
/** Outbound/routing compiler only. TUN/DNS/physical binding must be supplied by a verified platform driver. */
export function compileCandidate(node: ProxyNode, mode: 'rule' | 'global', rules: Rules) {
  return { log: { loglevel: 'warning', access: 'none' }, outbounds: [compileOutbound(node), { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }], routing: compileRouting(mode, rules) };
}
