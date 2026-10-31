import { createPrivateKey, createPublicKey, sign, generateKeyPairSync } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { strictJson } from '../src/domain/json';
import { validateBuild } from '../src/domain/trust';
import { PolicySchema } from '../src/shared/schema';
import { ReleaseSchema, verifyRelease } from '../src/services/update';
import { verifyPolicy } from '../src/services/policy';
import { KEY_ID } from '../server/src/signing';
async function main() {
  const [action, kind, input, keyPath, output] = process.argv.slice(2);
  if (action === 'generate-key' && kind && !input) {
    const keys = generateKeyPairSync('ed25519'); await mkdir(kind, { recursive: true, mode: 0o700 });
    await writeFile(join(kind, 'private.pem'), keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    await writeFile(join(kind, 'public.pem'), keys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644, flag: 'wx' }); console.log('Key pair written. Keep the private key outside the repository and client bundle.'); return;
  }
  if (!['policy', 'release'].includes(kind ?? '') || !input || !keyPath) throw new Error('usage');
  if (action === 'verify') {
    const config = validateBuild(strictJson(await readFile(keyPath, 'utf8'))); const envelope = await readFile(input, 'utf8');
    if (kind === 'policy') verifyPolicy(envelope, config, null, Date.now()); else verifyRelease(envelope, config, null, Date.now());
    console.log('Signature, schema and trust scope verified. Publication high-water must still be checked.'); return;
  }
  if (action !== 'sign' || !output) throw new Error('usage');
  const raw = await readFile(input); const payload = strictJson(raw.toString('utf8')); (kind === 'policy' ? PolicySchema : ReleaseSchema).parse(payload);
  const key = createPrivateKey(await readFile(keyPath)); if (key.asymmetricKeyType !== 'ed25519') throw new Error('key');
  const signature = sign(null, Buffer.concat([Buffer.from(kind === 'policy' ? 'v2board-client-policy-v1\n' : 'v2board-client-release-v1\n'), raw]), key);
  await writeFile(output, JSON.stringify({ keyId: KEY_ID, payload: raw.toString('base64url'), signature: signature.toString('base64url') }, null, 2), { flag: 'wx' }); console.log('Signed envelope written without changing the payload bytes.');
}
void main().catch(() => { console.error('Usage: npm run sign -- generate-key <directory> | sign <policy|release> <payload.json> <private.pem> <out.json> | verify <policy|release> <envelope.json> <build.json>.'); process.exitCode = 1; });
