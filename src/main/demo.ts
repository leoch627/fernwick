import { randomUUID } from 'node:crypto';
import type { PanelAdapter } from '../services/panel';
import type { Account } from '../shared/schema';
import type { Session } from '../domain/model';
/** Explicit, development-only fixture. No test endpoint is used by the production adapter. */
export class DemoPanel implements PanelAdapter {
  async login(_endpoint: string, email: string): Promise<Session> { return { accountId: 'demo-account', email, token: 'development-fixture-only', generation: randomUUID() }; }
  async fetchAccount(_endpoint: string, session: Session): Promise<Account> {
    return { accountId: session.accountId, email: session.email, planName: '星轨 · 标准套餐（示例）', sessionStatus: 'valid', serviceAllowed: 'yes', banned: 'no', hasPlan: 'yes', trafficExhausted: 'no', expiryKind: 'finite', expiresAt: new Date(Date.now() + 19 * 86400000).toISOString(), quotaKind: 'finite', usedBytes: '31353261260', quotaBytes: '214748364800', resetAt: null, observedAt: new Date().toISOString(), sourceEndpointId: 'fixture', authorizationEvidence: 'explicit-development-fixture' };
  }
  async fetchSubscriptionDescriptor() { return { url: 'https://fixture.invalid/subscription', format: 'v2ray-uri-base64-v1' as const, authoritativeEmpty: false }; }
  async fetchNodes() {
    return ['日本 · 东京 01', '新加坡 · 狮城 01', '香港 · 港岛 01', '美国 · 洛杉矶 01'].map((name, i) => `vless://00000000-0000-4000-8000-00000000000${i}@node${i}.example.invalid:443?security=tls&type=tcp&sni=node${i}.example.invalid#${encodeURIComponent(name)}`).join('\n');
  }
}
