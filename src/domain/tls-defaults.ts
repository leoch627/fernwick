/** X25519 is a key exchange group, not an Xray fingerprint name. */
export const defaultTlsProfile = {
  name: 'x25519',
  // Stands in a parsed node for "no fingerprint given" and is part of its ID; what is sent
  // is chosen by modernFingerprint.
  fingerprint: 'hellochrome_120',
  keyShareGroup: 29,
} as const;
/** A current browser's ClientHello, whatever the subscription names: Safari 26.3 for
 * Safari or iOS, else Chrome 133. Both send an X25519 key share, which REALITY needs. */
export function modernFingerprint(requested: string | undefined): string {
  const value = (requested ?? '').toLowerCase();
  return value === 'safari' || value === 'ios' || value.startsWith('hellosafari') || value.startsWith('helloios') ? 'hellosafari_26_3' : 'hellochrome_133';
}
