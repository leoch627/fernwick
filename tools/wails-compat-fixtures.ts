/** Frozen TypeScript oracle for the Go migration. Run with node --import tsx. */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { parseSubscription } from '../src/domain/subscription';
import { compileOutbound } from '../src/domain/compiler';
import { compileProbe } from '../src/domain/core-config';
import { uri, options } from '../tests/fixtures';

const vmess = (changes: Record<string, unknown> = {}) => 'vmess://' + Buffer.from(JSON.stringify({
  v: '2', ps: 'node', add: 'node.invalid', port: '443', id: '00000000-0000-4000-8000-000000000001',
  aid: '0', net: 'ws', type: 'none', path: '/', host: 'node.invalid', tls: 'tls', scy: 'auto', allowInsecure: 0, pcs: '', ...changes,
})).toString('base64');
const cases = [
  ['vless-tls-default', uri],
  ['vless-tls-explicit', uri.replace('#Tokyo', '&fp=firefox#Tokyo')],
  ['vless-reality-default', uri.replace('security=tls', 'security=reality&pbk=' + 'A'.repeat(43) + '&sid=1234&flow=xtls-rprx-vision')],
  ['vless-reality-explicit', uri.replace('security=tls', 'security=reality&pbk=' + 'A'.repeat(43) + '&sid=&fp=chrome')],
  ['vless-ipv6', uri.replace('node.example.invalid:443', '[2001:0db8:0:0:0:0:0:1]:443')],
  ['vless-ipv4-mapped-ipv6', uri.replace('node.example.invalid:443', '[::ffff:192.0.2.1]:443')],
  ['vless-numeric-custom-scheme-host', uri.replace('node.example.invalid:443', '127.000.000.001:443')],
  ['vless-utf16-name', uri.replace('Tokyo', encodeURIComponent('Tokyo 🚄 東京'))],
  ['vless-neutral-fields', uri.replace('#Tokyo', '&host=&path=&headerType=none&quicSecurity=none&serviceName=&insecure=0&pcs=#Tokyo')],
  ['vless-bad-fingerprint', uri.replace('#Tokyo', '&fp=x25519#Tokyo')],
  ['vless-insecure', uri.replace('#Tokyo', '&insecure=1#Tokyo')],
  ['trojan-default', 'trojan://secret@node.invalid:443?allowInsecure=0&peer=node.invalid&sni=node.invalid&pcs=&type=tcp#node'],
  ['trojan-escaping', 'trojan://' + encodeURIComponent('quotes" slash\\ <>& / \u2028\u2029 🚄') + '@node.invalid:443#escaped'],
  ['trojan-query-plus', 'trojan://secret@node.invalid:443?sni=hello+world#query'],
  ['trojan-query-invalid-bytes', 'trojan://secret@node.invalid:443?sni=%FF%FF#query'],
  ['trojan-query-truncated-utf8', 'trojan://secret@node.invalid:443?sni=%E1%80#query'],
  ['trojan-query-surrogate', 'trojan://secret@node.invalid:443?sni=%ED%A0%80#query'],
  ['vless-url-dot-path', uri.replace(':443?', ':443/./?')],
  ['vless-url-parent-path', uri.replace(':443?', ':443/x/%2e%2E?')],
  ['ss-base64', 'ss://' + Buffer.from('aes-128-gcm:secret').toString('base64url') + '@node.invalid:443#node'],
  ['ss-user-password', 'ss://aes-256-gcm:' + encodeURIComponent('p:a@ss"\\<>&\u2028\u2029') + '@node.invalid:443#node'],
  ['ss-unsupported-method', 'ss://' + Buffer.from('rc4:secret').toString('base64url') + '@node.invalid:443#node'],
  ['vmess-default', vmess()],
  ['vmess-explicit', vmess({ fp: 'safari', path: '/path?x=<>&"\\\u2028\u2029🚄' })],
  ['vmess-surrogate', vmess({ path: '/unpaired-\ud800-and-\udfff-paired-\ud83d\ude84' })],
  ['vmess-number-port', vmess({ port: 443, scy: 'aes-128-gcm', aid: 0 })],
  ['vmess-scoped-ipv6', vmess({ add: 'fe80::1%en0' })],
  ['vmess-number-array-port', vmess({ port: [443] })],
  ['vmess-js-numeric-port', vmess({ port: '0x1bb', aid: -0 })],
  ['vmess-pinned-certificate', vmess({ pcs: 'certificate-pin' })],
  ['unsupported', 'hysteria2://password@node.invalid:443#<>&"\\\u2028\u2029'],
  ['base64-list', Buffer.from(uri + '\n' + vmess()).toString('base64')],
  ['quarantine', uri + '\nvless://bad@node.invalid:443#bad'],
  ['deduplicate', uri + '\n' + uri.replace('#Tokyo', '#renamed')],
] as const;
const auth = { port: 49152, user: 'random-session', password: 'random-session-password' };
const fixtures = cases.map(([name, raw]) => {
  const parsed = parseSubscription(raw, options);
  return { name: String(name), raw, options, parsed, outbounds: parsed.nodes.map(node => node.compatible ? compileOutbound(node) : null), probes: parsed.nodes.map(node => node.compatible ? compileProbe(node, auth) : null) };
});
fixtures.push({ name: 'unconfirmed', raw: uri, options: { ...options, confirmedTcpUdp: false }, parsed: parseSubscription(uri, { ...options, confirmedTcpUdp: false }), outbounds: [null], probes: [null] });
const target = resolve('desktop/core/testdata/subscriptions.json');
const output = JSON.stringify({ generatedBy: 'tools/wails-compat-fixtures.ts (TypeScript reference implementation)', auth, fixtures }, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (readFileSync(target, 'utf8') !== output) throw new Error('Wails subscription compatibility fixtures are stale; run node --import tsx tools/wails-compat-fixtures.ts');
  console.log(`Verified ${fixtures.length} TypeScript subscription compatibility cases`);
} else {
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, output);
  console.log(`Wrote ${fixtures.length} subscription compatibility cases to ${target}`);
}
