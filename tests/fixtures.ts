import { createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import development from '../config/development.json';
import { BuildSchema, type Account, type Policy } from '../src/shared/schema';
import { createSnapshot } from '../src/domain/authorization';
import { parseSubscription } from '../src/domain/subscription';
import type { Session } from '../src/domain/model';
export const now = Date.parse('2026-10-31T00:00:00Z');
export const key = generateKeyPairSync('ed25519');
export const build = BuildSchema.parse({ ...development, policyKeys: { p1: key.publicKey.export({ type: 'spki', format: 'pem' }) }, updateKeys: { r1: key.publicKey.export({ type: 'spki', format: 'pem' }) }, protocolCapabilities: ['vless-tls', 'vless-reality', 'vmess-ws-tls', 'trojan-tls', 'shadowsocks-aead'], nodeCapabilitiesConfirmed: true });
export const session: Session = { accountId: 'alice@example.invalid', email: 'alice@example.invalid', token: 'SECRET_ACCOUNT_TOKEN', generation: 'session-1' };
export const account: Account = { accountId: session.accountId, email: session.email, planName: 'Fixture', sessionStatus: 'valid', serviceAllowed: 'yes', banned: 'no', hasPlan: 'yes', trafficExhausted: 'no', expiryKind: 'finite', expiresAt: new Date(now + 5 * 86400000).toISOString(), quotaKind: 'finite', usedBytes: '1024', quotaBytes: '1073741824', resetAt: null, observedAt: new Date(now).toISOString(), sourceEndpointId: 'primary', authorizationEvidence: 'test-contract-only' };
export const uri = 'vless://00000000-0000-4000-8000-000000000001@node.example.invalid:443?security=tls&type=tcp&sni=node.example.invalid#Tokyo';
export const options = { source: 'test-fixture', capabilities: build.protocolCapabilities, confirmedTcpUdp: true };
export const parsed = parseSubscription(uri, options);
export const snapshot = createSnapshot(build, session, account, parsed, now, 86400, 1);
export const policy: Policy = { schemaVersion: 2, policyVersion: 1, productId: build.productId, environment: build.environment, channel: build.channel, issuedAt: new Date(now).toISOString(), notBefore: new Date(now).toISOString(), expiresAt: new Date(now + 7 * 86400000).toISOString(), requiredCapabilities: ['tun', 'policy-schema-2'], endpoints: { orderedIds: ['primary', 'backup'], temporarilyDisabledIds: [] }, refresh: { subscriptionIntervalSec: 1800, accountIntervalSec: 300, policyIntervalSec: 900, maxSnapshotAgeSec: 86400 }, ui: { expiryReminderDays: [7, 3], showTrafficSummary: true, announcement: null }, links: { website: 'https://host.leiterup.de/', renew: 'https://host.leiterup.de/', help: 'https://host.leiterup.de/' }, nodeOperations: [], routing: { templateId: 'cn-direct-default-proxy-v1', dnsTemplateId: 'real-dns-split-v1', resource: null }, maintenance: null, update: { checkIntervalSec: 21600, noticeText: null } };
export function envelope(payload: unknown, purpose = 'v2board-client-policy-v1', keyId = 'p1') {
  const raw = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)); return JSON.stringify({ keyId, payload: raw.toString('base64url'), signature: sign(null, Buffer.concat([Buffer.from(purpose + '\n'), raw]), key.privateKey).toString('base64url') });
}
export function deferred<T>() { let resolve!: (value: T) => void; let reject!: (error: unknown) => void; const promise = new Promise<T>((r, j) => { resolve = r; reject = j; }); return { promise, resolve, reject }; }
