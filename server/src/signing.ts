// Ed25519 envelopes in the exact format the client verifies (src/services/policy.ts verifyEnvelope):
// signature over `${purpose}\n` + raw payload bytes, both base64url without padding.
export type Purpose = 'v2board-client-release-v1' | 'v2board-client-policy-v1';
export interface Envelope { keyId: string; payload: string; signature: string }

export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function importSigningKey(pem: string): Promise<CryptoKey> {
  const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(body), c => c.charCodeAt(0));
  return crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
}

export async function signEnvelope(key: CryptoKey, keyId: string, purpose: Purpose, payload: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const message = new Uint8Array([...new TextEncoder().encode(`${purpose}\n`), ...bytes]);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, message));
  const envelope: Envelope = { keyId, payload: base64url(bytes), signature: base64url(signature) };
  return JSON.stringify(envelope);
}

/** Constant-time comparison of a presented bearer token against the configured one. */
export async function sameSecret(presented: string, expected: string): Promise<boolean> {
  if (!expected) return false;
  const digest = async (value: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  const [a, b] = await Promise.all([digest(presented), digest(expected)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
