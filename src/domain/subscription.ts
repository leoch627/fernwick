import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import type { ParsedNodes, ProxyNode } from './model';
import type { BuildConfig } from '../shared/schema';
import { AppError, assert } from '../shared/errors';
import { strictJson } from './json';
import { defaultTlsProfile, supportedFingerprints } from './tls-defaults';
const bad = () => new AppError('SUBSCRIPTION_INVALID');
export function decodeBase64(value: string): Buffer {
  assert(value.length > 0 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value) && value.replace(/=+$/, '').length % 4 !== 1, 'SUBSCRIPTION_INVALID');
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const result = Buffer.from(normalized, 'base64');
  assert(result.toString('base64').replace(/=+$/, '') === normalized, 'SUBSCRIPTION_INVALID'); return result;
}
const utf8 = (buffer: Uint8Array) => new TextDecoder('utf-8', { fatal: true }).decode(buffer);
function field(value: unknown, max = 256): string { assert(typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f]/.test(value), 'SUBSCRIPTION_INVALID'); return value; }
function port(value: unknown) { const n = Number(value); assert(Number.isInteger(n) && n >= 1 && n <= 65535, 'SUBSCRIPTION_INVALID'); return n; }
function host(value: unknown) { const h = field(value).replace(/^\[|\]$/g, ''); assert(isIP(h) || /^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(h), 'SUBSCRIPTION_INVALID'); return h.toLowerCase(); }
function uuid(value: unknown) { const v = field(value); assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v), 'SUBSCRIPTION_INVALID'); return v.toLowerCase(); }
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
type Capability = BuildConfig['protocolCapabilities'][number];
export interface ParserOptions { capabilities: readonly Capability[]; confirmedTcpUdp: boolean; authoritativeEmpty?: boolean; source: string; }
function parseLine(line: string, index: number, options: ParserOptions): ProxyNode {
  assert(line.length <= 16384, 'SUBSCRIPTION_INVALID');
  const node: ProxyNode = { id: '', name: '', group: '全部节点', region: null, order: index, protocol: 'unsupported', host: '', port: 0, credential: '', transport: 'tcp', security: 'none', compatible: false, incompatibility: null, tcp: options.confirmedTcpUdp, udp: options.confirmedTcpUdp, ipv6: 'unknown', connectionFingerprint: '', source: options.source };
  let capability: Capability | undefined;
  if (line.startsWith('vmess://')) {
    const data = strictJson(utf8(decodeBase64(line.slice(8))), 16384) as Record<string, unknown>;
    assert(data && typeof data === 'object' && !Array.isArray(data), 'SUBSCRIPTION_INVALID');
    const allowed = new Set(['v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp', 'allowInsecure', 'pcs']);
    assert(Object.keys(data).every(k => allowed.has(k)), 'SUBSCRIPTION_INVALID');
    node.protocol = 'vmess'; node.host = host(data.add); node.port = port(data.port); node.credential = uuid(data.id); node.name = typeof data.ps === 'string' && data.ps ? field(data.ps) : `VMess ${index + 1}`;
    if (String(data.aid ?? '0') !== '0' || data.net !== 'ws' || data.tls !== 'tls' || !['auto', 'aes-128-gcm', 'chacha20-poly1305', undefined, ''].includes(data.scy as string) || (data.type && data.type !== 'none') || data.alpn || ![undefined, 0, '0', false].includes(data.allowInsecure as never) || data.pcs) node.incompatibility = '仅支持 VMess AEAD / WebSocket / TLS 模板，禁止弱化 TLS 或忽略证书固定';
    node.method = String(data.scy || 'auto'); node.transport = 'ws'; node.security = 'tls'; node.sni = field(data.sni || data.host || data.add); node.wsHost = field(data.host || data.sni || data.add); node.wsPath = field(data.path || '/', 2048);
    if (data.fp) node.fingerprint = field(data.fp);
    capability = 'vmess-ws-tls';
  } else if (/^(vless|trojan|ss):\/\//.test(line)) {
    const u = new URL(line); const q = u.searchParams;
    assert(new Set([...q.keys()]).size === [...q.keys()].length, 'SUBSCRIPTION_INVALID');
    const allowed = u.protocol === 'ss:' ? [] : ['type', 'security', 'sni', 'flow', 'pbk', 'sid', 'fp', 'encryption', 'host', 'path', 'headerType', 'quicSecurity', 'serviceName', 'insecure', 'allowInsecure', 'pcs', 'peer'];
    assert([...q.keys()].every(k => allowed.includes(k)), 'SUBSCRIPTION_INVALID');
    node.host = host(u.hostname); node.port = port(u.port); node.name = u.hash ? field(decodeURIComponent(u.hash.slice(1))) : `节点 ${index + 1}`;
    assert(!u.pathname || u.pathname === '/', 'SUBSCRIPTION_INVALID');
    if (u.protocol === 'ss:') {
      node.protocol = 'shadowsocks';
      const raw = u.password ? `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}` : utf8(decodeBase64(decodeURIComponent(u.username)));
      const split = raw.indexOf(':'); assert(split > 0, 'SUBSCRIPTION_INVALID'); node.method = raw.slice(0, split); node.credential = field(raw.slice(split + 1), 1024);
      if (!['chacha20-ietf-poly1305', 'aes-128-gcm', 'aes-256-gcm'].includes(node.method)) node.incompatibility = '不支持的 Shadowsocks 加密方法';
      capability = 'shadowsocks-aead';
    } else {
      assert(!u.password, 'SUBSCRIPTION_INVALID'); node.protocol = u.protocol === 'vless:' ? 'vless' : 'trojan';
      node.credential = node.protocol === 'vless' ? uuid(decodeURIComponent(u.username)) : field(decodeURIComponent(u.username), 1024);
      const security = q.get('security') ?? (node.protocol === 'trojan' ? 'tls' : 'none');
      node.security = security === 'tls' || security === 'reality' ? security : 'none';
      if ((q.get('type') || 'tcp') !== 'tcp' || !['tls', 'reality'].includes(security) || (node.protocol === 'trojan' && security !== 'tls') || (q.has('encryption') && q.get('encryption') !== 'none')) node.incompatibility = '不支持的传输或安全组合';
      node.sni = field(q.get('sni') || q.get('peer') || node.host); node.flow = q.get('flow') || '';
      if (q.get('peer') && q.get('sni') && q.get('peer') !== q.get('sni')) node.incompatibility = 'TLS serverName 字段冲突';
      if (['host', 'path', 'serviceName', 'pcs'].some(k => !!q.get(k)) || ['headerType', 'quicSecurity'].some(k => q.has(k) && !['', 'none'].includes(q.get(k)!)) || ['insecure', 'allowInsecure'].some(k => q.has(k) && !['0', 'false', ''].includes(q.get(k)!))) node.incompatibility = '不支持的安全或传输参数';
      if (!['', 'xtls-rprx-vision'].includes(node.flow) || (node.protocol === 'trojan' && node.flow)) node.incompatibility = '不支持的 flow';
      if (q.has('fp')) node.fingerprint = field(q.get('fp'));
      if (security === 'reality') {
        node.publicKey = field(q.get('pbk')); node.shortId = q.get('sid') || '';
        assert(/^[A-Za-z0-9_-]{43}$/.test(node.publicKey) && /^(?:[a-f0-9]{2}){0,8}$/i.test(node.shortId), 'SUBSCRIPTION_INVALID');
        capability = 'vless-reality';
      } else { assert(!q.has('pbk') && !q.has('sid'), 'SUBSCRIPTION_INVALID'); capability = node.protocol === 'vless' ? 'vless-tls' : 'trojan-tls'; }
    }
  } else if (/^(?:hysteria2?|hy2|tuic|wireguard|ssr|socks5?|https?):\/\/\S+$/i.test(line)) {
    node.name = `不兼容节点 ${index + 1}`; node.incompatibility = '协议不在首版支持范围';
    node.connectionFingerprint = hash(line); node.id = node.connectionFingerprint; return node;
  } else { throw bad(); }
  if (node.security === 'tls' || node.security === 'reality') node.fingerprint ??= defaultTlsProfile.fingerprint;
  if (node.fingerprint && !supportedFingerprints.includes(node.fingerprint)) node.incompatibility = '未验证的 TLS 指纹';
  if (capability && !options.capabilities.includes(capability)) node.incompatibility = '此协议模板尚未通过部署验证';
  if (!options.confirmedTcpUdp) node.incompatibility ||= '尚未确认节点 TCP / UDP 能力';
  const { id: _id, name: _name, order: _order, group: _group, region: _region, compatible: _compatible, incompatibility: _reason, source: _source, connectionFingerprint: _fp, ...connection } = node;
  node.connectionFingerprint = hash(connection); node.id = node.connectionFingerprint; node.compatible = !node.incompatibility; return node;
}
export function parseSubscription(raw: string, options: ParserOptions): ParsedNodes {
  try {
    assert(Buffer.byteLength(raw) <= 14 * 1024 * 1024, 'SUBSCRIPTION_INVALID');
    let text = raw.trim();
    if (!text) { if (options.authoritativeEmpty) return { nodes: [], quarantined: [], authoritativeEmpty: true }; throw bad(); }
    if (!text.includes('://')) text = utf8(decodeBase64(text.replace(/[\r\n]/g, '')));
    assert(Buffer.byteLength(text) <= 10 * 1024 * 1024 && !text.trimStart().startsWith('<'), 'SUBSCRIPTION_INVALID');
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    assert(lines.length > 0 && lines.length <= 5000, 'SUBSCRIPTION_INVALID');
    // URI format has no authoritative completeness marker; a malformed line boundary rejects the response.
    assert(lines.every(l => /^[a-z][a-z0-9+.-]*:\/\//i.test(l)), 'SUBSCRIPTION_INVALID');
    const nodes: ProxyNode[] = [], quarantined: ParsedNodes['quarantined'] = []; const ids = new Set<string>();
    for (const [index, line] of lines.entries()) {
      try { const node = parseLine(line, index, options); if (ids.has(node.id)) continue; ids.add(node.id); nodes.push(node); }
      catch { quarantined.push({ index, reason: '节点字段不符合冻结格式' }); }
    }
    assert(nodes.length > 0, 'SUBSCRIPTION_INVALID'); return { nodes, quarantined, authoritativeEmpty: false };
  } catch { throw bad(); }
}
