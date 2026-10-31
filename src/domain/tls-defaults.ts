/** X25519 is a key exchange group, not an Xray fingerprint name. */
export const defaultTlsProfile = {
  name: 'x25519',
  // The pinned core's classic Chrome 120 ClientHello sends an X25519 key share (not its PQ variant).
  fingerprint: 'hellochrome_120',
  keyShareGroup: 29,
} as const;
export const supportedFingerprints = ['chrome', 'firefox', 'safari', 'edge', 'ios', 'android', 'randomized', defaultTlsProfile.fingerprint] as readonly string[];
