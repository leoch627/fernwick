import { createHash } from 'node:crypto';

/** One key signs both the release index and the policy; the purpose prefix keeps the two apart. */
export const KEY_ID = 'key-1';

/** The endpoint's /admin bearer token, derived from the signing key (server/signing.go adminToken). */
export function adminToken(signingKey: string): string {
  const body = signingKey.replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s+/g, '');
  return createHash('sha256').update(`v2board-client-admin-v1\n${body}`).digest('hex');
}
