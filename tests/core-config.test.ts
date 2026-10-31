import { expect, it } from 'vitest';
import { compileProbe, compileTun } from '../src/domain/core-config';
import { RulesSchema } from '../src/domain/compiler';
import { parsed } from './fixtures';
const node = parsed.nodes[0]!;
const rules = { schemaVersion: 1 as const, directDomains: ['example.cn'], proxyDomains: ['example.org'], blockedDomains: [], directIPs: [] };
const auth = { port: 49152, user: 'random-session', password: 'random-session-password' };
const network = { platform: 'linux' as const, interface: 'eth0', resolvedNodeAddress: '203.0.113.10', bootstrapDns: 'https://223.5.5.5/dns-query', proxyDns: 'https://1.1.1.1/dns-query' };
it('isolated probes have only an authenticated loopback SOCKS inbound and the selected proxy outbound', () => {
  const config = compileProbe(node, auth); expect(config.inbounds).toHaveLength(1); expect(config.outbounds).toHaveLength(1);
  expect(config.inbounds[0]).toMatchObject({ listen: '127.0.0.1', settings: { auth: 'password', udp: false } });
  expect(JSON.stringify(config)).not.toContain('freedom'); expect(JSON.stringify(config)).not.toContain('tun');
});
it('TUN config preserves TLS identity while binding the resolved node and physical interface', () => {
  const config = compileTun(node, 'rule', rules, network, auth); const proxy = config.outbounds[0]!;
  expect(JSON.stringify(proxy)).toContain('203.0.113.10'); expect(JSON.stringify(proxy)).toContain('node.example.invalid');
  expect(proxy.streamSettings?.sockopt).toMatchObject({ interface: 'eth0' });
  expect(config.inbounds[0]?.settings).toMatchObject({ autoSystemRoutingTable: [], autoSystemDnsToGateway: false });
});
it('explicit proxy DNS wins over an overlapping direct suffix and matching failures cannot fall back', () => {
  const config = compileTun(node, 'rule', { ...rules, proxyDomains: ['force.example.cn'] }, network, auth);
  expect(config.dns.disableFallbackIfMatch).toBe(true);
  expect(config.dns.servers[0]).toMatchObject({ tag: 'dns-proxy', domains: ['domain:force.example.cn'], skipFallback: true, finalQuery: true });
  expect(config.dns.servers[1]).toMatchObject({ tag: 'dns-direct', domains: ['domain:example.cn'], skipFallback: true, finalQuery: true });
  expect(config.dns.servers[2]).toMatchObject({ tag: 'dns-proxy', skipFallback: false, finalQuery: true });
  const global = compileTun(node, 'global', rules, network, auth); expect(global.dns.servers).toHaveLength(1);
  expect(global.dns.servers[0]?.tag).toBe('dns-proxy'); expect(JSON.stringify(global)).not.toContain('example.cn');
});
it.each(['http://1.1.1.1/dns-query', 'https://unresolved.invalid/dns-query', 'https://user:pass@1.1.1.1/dns-query', 'https://1.1.1.1/dns-query?token=x'])('rejects an unsafe DNS template: %s', value => {
  expect(() => compileTun(node, 'rule', rules, { ...network, proxyDns: value }, auth)).toThrow();
});
it('rejects unresolved node addresses and raw helper fields', () => {
  expect(() => compileTun(node, 'rule', rules, { ...network, resolvedNodeAddress: 'node.invalid' }, auth)).toThrow();
  expect(() => compileTun(node, 'rule', rules, { ...network, executable: '/tmp/program' } as typeof network, auth)).toThrow();
});
it('rejects invalid IP/CIDR and domain rules before activation', () => {
  for (const invalid of ['999.1.2.3/24', '192.0.2.0/64', '2001:db8::/129', '1.1.1.1/01', 'bad']) expect(RulesSchema.safeParse({ ...rules, directIPs: [invalid] }).success).toBe(false);
  for (const invalid of ['bad..domain', '-bad.domain', 'bad-.domain', '.bad.domain', 'bad.domain.']) expect(RulesSchema.safeParse({ ...rules, directDomains: [invalid] }).success).toBe(false);
  expect(RulesSchema.safeParse({ ...rules, directIPs: ['192.0.2.0/24', '2001:db8::/32'] }).success).toBe(true);
});
