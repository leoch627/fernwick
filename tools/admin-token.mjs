// Print the endpoint's /admin bearer token for the key in $SIGNING_KEY (CI) or the PEM file given.
// Same derivation as server/signing.go adminToken and tools/signing.ts; no dependencies.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const key = process.argv[2] ? readFileSync(process.argv[2], 'utf8') : process.env.SIGNING_KEY;
if (!key) { console.error('Usage: SIGNING_KEY=... node tools/admin-token.mjs | node tools/admin-token.mjs private.pem'); process.exit(1); }
const body = key.replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s+/g, '');
process.stdout.write(createHash('sha256').update(`v2board-client-admin-v1\n${body}`).digest('hex'));
