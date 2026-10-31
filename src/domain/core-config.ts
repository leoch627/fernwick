import { isIP } from 'node:net';
import { z } from 'zod';
import type { ProxyNode } from './model';
import { compileOutbound, compileRouting, lanCIDRs, RulesSchema, type Rules } from './compiler';
import { assert } from '../shared/errors';
import { tunNames } from './identity';
import type { ProbeCredentials } from '../platform/core';

const binding = z.string().min(1).max(128).regex(/^[\p{L}\p{N} _.:{}-]+$/u);
const resolver = z.string().url().superRefine((value, context) => {
  const url = new URL(value);
  if (url.protocol !== 'https:' || !isIP(url.hostname.replace(/^\[|\]$/g, '')) || url.username || url.password || url.search || url.hash || url.port)
    context.addIssue({ code: 'custom', message: 'DNS must use a certificate-verified HTTPS endpoint at a fixed literal IP' });
});
export const CoreNetworkSchema = z.object({
  platform: z.enum(['linux', 'darwin', 'win32']), interface: binding,
  resolvedNodeAddress: z.string().refine(value => !!isIP(value)),
  bootstrapDns: resolver, proxyDns: resolver,
}).strict();
export type CoreNetwork = z.infer<typeof CoreNetworkSchema>;

function healthInbound(auth: ProbeCredentials) {
  assert(Number.isInteger(auth.port) && auth.port >= 1024 && auth.port <= 65535 && auth.user.length >= 1 && auth.user.length <= 255 && auth.password.length >= 16 && auth.password.length <= 255);
  return { tag: 'health', listen: '127.0.0.1', port: auth.port, protocol: 'socks', settings: { auth: 'password', accounts: [{ user: auth.user, pass: auth.password }], udp: false } };
}
export function compileProbe(node: ProxyNode, auth: ProbeCredentials) {
  return { log: { loglevel: 'none', access: 'none', error: 'none' }, inbounds: [healthInbound(auth)],
    outbounds: [compileOutbound(node)], routing: { domainStrategy: 'AsIs', rules: [{ type: 'field', inboundTag: ['health'], outboundTag: 'proxy' }] } };
}

/** Executable template, not permission to take over a host. The protected helper must supply/own OS state. */
export function compileTun(node: ProxyNode, mode: 'rule' | 'global', rules: Rules, input: CoreNetwork, auth: ProbeCredentials) {
  const network = CoreNetworkSchema.parse(input); RulesSchema.parse(rules);
  const proxy = compileOutbound({ ...node, host: network.resolvedNodeAddress });
  proxy.streamSettings.sockopt = { interface: network.interface, domainStrategy: 'UseIP' };
  const directDomains = mode === 'rule' ? [...rules.directDomains.map(value => `domain:${value}`), ...(rules.directFullDomains ?? []).map(value => `full:${value}`)] : [];
  const proxyDomains = mode === 'rule' ? rules.proxyDomains.map(value => `domain:${value}`) : [];
  const tunName = tunNames[network.platform];
  const routing = compileRouting(mode, rules);
  return {
    log: { loglevel: 'none', access: 'none', error: 'none' },
    inbounds: [{ tag: 'tun', protocol: 'tun', settings: {
      name: tunName, mtu: 1500, gateway: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
      autoSystemRoutingTable: [], autoOutboundsInterface: network.interface, autoSystemDnsToGateway: false,
    }, sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true } }, healthInbound(auth)],
    dns: { tag: 'dns-proxy', queryStrategy: 'UseIP', disableFallbackIfMatch: true, useSystemHosts: false, servers: [
      ...(proxyDomains.length ? [{ address: network.proxyDns, domains: proxyDomains, skipFallback: true, tag: 'dns-proxy', finalQuery: true }] : []),
      ...(directDomains.length ? [{ address: network.bootstrapDns, domains: directDomains, skipFallback: true, tag: 'dns-direct', finalQuery: true }] : []),
      { address: network.proxyDns, tag: 'dns-proxy', skipFallback: false, finalQuery: true },
    ] },
    outbounds: [proxy,
      { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIP', finalRules: [{ action: 'allow', ip: lanCIDRs }] }, streamSettings: { sockopt: { interface: network.interface, domainStrategy: 'UseIP' } } },
      { tag: 'dns-out', protocol: 'dns', settings: { rules: [{ action: 'hijack', qType: '1,28' }, { action: 'return', rCode: 5 }] } },
      { tag: 'block', protocol: 'blackhole' },
    ],
    routing: { ...routing, rules: [
      { type: 'field', inboundTag: ['dns-direct'], outboundTag: 'direct' },
      { type: 'field', inboundTag: ['dns-proxy'], outboundTag: 'proxy' },
      ...routing.rules,
    ] },
  };
}
