import https from 'node:https';
import { AppError } from '../shared/errors';
import { httpsUrl } from '../domain/trust';
import { Budget } from '../domain/time';
export interface HttpResponse { status: number; headers: Record<string, string | undefined>; body: string; }
export interface HttpRequest { url: string; method?: 'GET' | 'POST'; headers?: Record<string, string>; body?: string; maxBytes?: number; }
export interface Transport { request(request: HttpRequest, budget: Budget): Promise<HttpResponse>; }
/** Explicit direct HTTPS path. Never consumes system proxy settings or follows redirects. */
export class DirectHttpsTransport implements Transport {
  async request(input: HttpRequest, budget: Budget): Promise<HttpResponse> {
    const url = httpsUrl(input.url); budget.check();
    return budget.run(signal => new Promise((resolve, reject) => {
      let total = 0; const chunks: Buffer[] = [];
      const req = https.request(url, { method: input.method ?? 'GET', headers: { 'cache-control': 'no-store', 'user-agent': 'V2BoardDesktop/0.1', ...input.headers }, agent: false, signal }, res => {
        const status = res.statusCode ?? 0;
        if (status >= 300 && status < 400) { res.destroy(); req.destroy(); reject(new AppError('CONTROL_UNAVAILABLE')); return; }
        res.on('data', (chunk: Buffer) => { total += chunk.length; if (total > (input.maxBytes ?? 512 * 1024)) { req.destroy(); reject(new AppError('CONTROL_UNAVAILABLE')); } else chunks.push(chunk); });
        res.on('error', () => reject(new AppError('CONTROL_UNAVAILABLE')));
        res.on('end', () => { const headers: HttpResponse['headers'] = {}; for (const [k, v] of Object.entries(res.headers)) headers[k] = Array.isArray(v) ? v.join(',') : v; resolve({ status, headers, body: Buffer.concat(chunks).toString('utf8') }); });
      });
      const connection = setTimeout(() => req.destroy(new Error('connect deadline')), Math.min(3000, budget.remaining));
      const timeout = setTimeout(() => req.destroy(new Error('request deadline')), Math.min(6000, budget.remaining));
      req.on('socket', socket => socket.once('secureConnect', () => clearTimeout(connection)));
      req.once('close', () => { clearTimeout(connection); clearTimeout(timeout); });
      req.on('error', () => reject(new AppError(signal.aborted ? 'CANCELLED' : 'CONTROL_UNAVAILABLE')));
      req.end(input.body);
    }));
  }
}
export function retryAfter(value: string | undefined, now = Date.now()): number {
  if (!value) return 30000; const n = Number(value);
  return Math.max(1000, Number.isFinite(n) ? n * 1000 : Date.parse(value) - now || 30000);
}
export function requireSuccess(response: HttpResponse, authentication: 'account' | 'subscription' | 'login' | 'public') {
  if (response.status === 429) throw new AppError('RATE_LIMITED', retryAfter(response.headers['retry-after']));
  if (response.status === 401 || response.status === 403) throw new AppError(authentication === 'account' ? 'AUTH_INVALID' : authentication === 'subscription' ? 'SUBSCRIPTION_CREDENTIAL_INVALID' : authentication === 'login' ? 'LOGIN_FAILED' : 'CONTROL_UNAVAILABLE');
  if (response.status < 200 || response.status >= 300) throw new AppError(authentication === 'login' && response.status < 500 ? 'LOGIN_FAILED' : 'CONTROL_UNAVAILABLE');
}
