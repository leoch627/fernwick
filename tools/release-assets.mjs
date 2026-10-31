// Release bookkeeping for CI, no dependencies:
//   node tools/release-assets.mjs manifest <target>   after electron-builder: rename installers, write release/manifest-<target>.json
//   node tools/release-assets.mjs payload <version>   in the publish job: print the Worker's /admin/release body
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readdir, readFile, rename, writeFile, copyFile } from 'node:fs/promises';
import { join } from 'node:path';

const TARGETS = {
  'linux-x64': { platform: 'linux', arch: 'x64', minimumOS: '24.04', files: [['.deb', 'deb', 'linux-amd64']], unpacked: 'linux-unpacked' },
  'win32-x64': { platform: 'win32', arch: 'x64', minimumOS: '10.0.22000', files: [['.exe', 'nsis', 'windows-x64']], unpacked: 'win-unpacked' },
  'darwin-arm64': { platform: 'darwin', arch: 'arm64', minimumOS: '14.0', files: [['.dmg', 'dmg', 'macos-arm64'], ['.zip', 'zip', 'macos-arm64']], unpacked: 'mac-arm64' },
  'darwin-x64': { platform: 'darwin', arch: 'x64', minimumOS: '14.0', files: [['.dmg', 'dmg', 'macos-x64'], ['.zip', 'zip', 'macos-x64']], unpacked: 'mac' },
};
const sha256 = path => new Promise((resolve, reject) => {
  const hash = createHash('sha256');
  createReadStream(path).on('data', chunk => hash.update(chunk)).on('end', () => resolve(hash.digest('hex'))).on('error', reject);
});
async function treeBytes(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory()) return stat.size;
  let total = 0;
  for (const entry of await readdir(path)) total += await treeBytes(join(path, entry));
  return total;
}

/**
 * The identity the native helper will demand of this update, read from the signed output itself so it
 * cannot disagree with the certificate used. Mirrors update_windows.go / update_darwin.go; anything
 * those would reject is 'unsigned', which makes the client open the download page instead.
 */
async function signedBy(platform, path) {
  if (platform === 'win32') {
    const subject = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      "$s=Get-AuthenticodeSignature -LiteralPath $env:SIGNED_FILE; if($s.Status -eq 'Valid'){$s.SignerCertificate.Subject}"],
    { env: { ...process.env, SIGNED_FILE: path }, encoding: 'utf8' }).stdout?.trim();
    return subject || 'unsigned';
  }
  if (platform === 'darwin') {
    const app = join(path, (await readdir(path)).find(n => n.endsWith('.app')));
    const team = /^TeamIdentifier=(.+)$/m.exec(spawnSync('/usr/bin/codesign', ['-dv', '--verbose=4', app], { encoding: 'utf8' }).stderr ?? '')?.[1];
    if (!team || team === 'not set') return 'unsigned';
    if (spawnSync('/usr/sbin/spctl', ['--assess', '--type', 'execute', app]).status !== 0) {
      console.log(`::warning::${app} is signed by team ${team} but Gatekeeper rejects it (not notarized?); publishing as unsigned.`);
      return 'unsigned';
    }
    return team;
  }
  return 'unsigned';
}

async function manifest(target) {
  const spec = TARGETS[target];
  if (!spec) throw new Error(`unknown target ${target}`);
  const config = JSON.parse(await readFile('dist/build-config.json', 'utf8'));
  const { version } = JSON.parse(await readFile('package.json', 'utf8'));
  const core = JSON.parse(await readFile('resources/core-lock.json', 'utf8'));
  const asset = core.assets.find(a => a.target === target);
  const names = await readdir('release');
  const files = [];
  for (const [extension, format, suffix] of spec.files) {
    const found = names.filter(n => n.endsWith(extension) && !n.endsWith('.blockmap'));
    if (found.length !== 1) throw new Error(`expected one ${extension} in release/, found ${found.length}`);
    // Spaces and non-ASCII product names make poor URLs; the stable product ID does not.
    const file = `${config.productId}-${version}-${suffix}${extension}`;
    await rename(join('release', found[0]), join('release', file));
    files.push({ file, platform: spec.platform, arch: spec.arch, format, bytes: (await lstat(join('release', file))).size, sha256: await sha256(join('release', file)) });
  }
  const unpacked = join('release', spec.unpacked);
  const unpackedBytes = await treeBytes(unpacked);
  const signatureIdentity = await signedBy(spec.platform, spec.platform === 'win32' ? join('release', files[0].file) : unpacked);
  const entries = files.map(f => ({ ...f, unpackedBytes, minimumOS: spec.minimumOS, coreVersion: core.version, coreSha256: asset.executableSha256, signatureIdentity }));
  await writeFile(join('release', `manifest-${target}.json`), JSON.stringify(entries, null, 2) + '\n');
  await copyFile('dist/build-config.json', join('release', 'build-config.json'));
  for (const e of entries) console.log(`${e.file}  ${e.bytes} bytes  sha256:${e.sha256}`);
}

async function payload(version) {
  const config = JSON.parse(await readFile('release/build-config.json', 'utf8'));
  const files = [];
  for (const name of (await readdir('release')).filter(n => /^manifest-.+\.json$/.test(n)).sort()) {
    for (const entry of JSON.parse(await readFile(join('release', name), 'utf8'))) {
      const { file, ...rest } = entry;
      files.push({ key: `releases/${version}/${file}`, ...rest });
    }
  }
  const brand = {
    productId: config.productId, name: config.name, environment: config.environment, channel: config.channel,
    endpointIds: config.apiEndpoints.map(e => e.id), links: config.links,
  };
  process.stdout.write(JSON.stringify({ brand, version, files }));
}

const [command, argument] = process.argv.slice(2);
(command === 'manifest' ? manifest(argument) : command === 'payload' ? payload(argument) : Promise.reject(new Error('usage')))
  .catch(error => { console.error(error.message); process.exitCode = 1; });
