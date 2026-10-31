const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { Arch } = require('builder-util');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');
const config = JSON.parse(fs.readFileSync('dist/build-config.json', 'utf8'));
process.umask(0o022);
// Must match tools/build-native.py: the helper verifies these executable names and install paths.
const packageName = config.productId;
const productName = config.name + (config.environment === 'test' ? ' Dev' : '');
// Without a Developer ID certificate, ad-hoc sign the whole bundle so Apple silicon gets a sealed, launchable app.
// Hardened runtime would make library validation reject Electron's own frameworks under an ad-hoc identity.
const macCertificate = !!(process.env.CSC_LINK || process.env.CSC_NAME);
// Installer scripts need the service ID that the helper derives from productId.
function render(template) {
  const output = path.join('work/packaging', template);
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, fs.readFileSync(path.join('packaging', template), 'utf8').replaceAll('@SERVICE_ID@', config.productId), { mode: 0o755 });
  return path.resolve(output);
}
// The helper embeds native/helper/build.json from its own native:build run. One built for another configuration
// (STARRAIL_BUILD_CONFIG set for npm run build but not for native:build) fails its identity check on users' machines.
function checkHelperConfiguration() {
  const helper = JSON.parse(fs.readFileSync('native/helper/build.json', 'utf8'));
  const { buildId } = JSON.parse(fs.readFileSync('resources/native-manifest.json', 'utf8'));
  const { version } = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const controlOrigins = [...new Set([
    ...config.apiEndpoints.map(e => e.baseUrl.replace(/\/+$/, '')), ...config.trustedSubscriptionOrigins, ...config.trustedResourceOrigins,
    ...[...config.policyUrls, ...config.updateFeedUrls].map(url => new URL(url).origin),
  ])].sort();
  const expected = {
    productId: config.productId, displayName: productName, helperLabel: `${config.appId}.helper`, environment: config.environment, channel: config.channel,
    version, controlOrigins, healthTargets: config.healthTargets, updateKeys: config.updateKeys, trustedUpdateOrigins: config.trustedUpdateOrigins, buildId,
  };
  const canonical = value => JSON.stringify(value, (_, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1))) : v);
  const wrong = Object.keys(expected).filter(key => canonical(helper[key]) !== canonical(expected[key]));
  if (wrong.length) throw new Error(`native/helper/build.json does not match dist/build-config.json (${wrong.join(', ')}). Run npm run native:build with the same STARRAIL_BUILD_CONFIG as npm run build.`);
}
async function normalizePermissions(directory) {
  await fs.promises.chmod(directory, 0o755);
  for (const entry of await fs.promises.readdir(directory, { withFileTypes: true })) {
    const location = path.join(directory, entry.name);
    if (entry.isDirectory()) await normalizePermissions(location);
    else if (entry.isFile()) { const stat = await fs.promises.stat(location); await fs.promises.chmod(location, stat.mode & 0o111 ? 0o755 : 0o644); }
  }
}
module.exports = {
  appId: config.appId,
  productName,
  directories: { output: 'release', buildResources: 'resources' },
  toolsets: { wine: '1.0.1' },
  files: ['dist/**/*', 'package.json'], asar: true, npmRebuild: false,
  extraResources: [{ from: 'THIRD_PARTY_NOTICES.md', to: 'THIRD_PARTY_NOTICES.md' }, { from: 'resources/licenses', to: 'licenses' }, { from: 'resources/core-lock.json', to: 'core-lock.json' }, { from: 'resources/rules', to: 'rules' }, { from: 'tools/import-rules.py', to: 'rules/import-rules.py' }],
  extraMetadata: { main: 'dist/main/main.cjs', desktopName: config.appId, homepage: config.links.website ?? undefined },
  beforePack: async () => {
    checkHelperConfiguration();
    if (config.environment === 'production') execFileSync(process.execPath, ['--import', 'tsx', 'tools/release-check.ts'], { stdio: 'inherit' });
  },
  afterPack: async context => {
    const target = `${context.electronPlatformName}-${Arch[context.arch]}`;
    const core = JSON.parse(fs.readFileSync('resources/core-lock.json', 'utf8')).assets.find(a => a.target === target);
    const native = JSON.parse(fs.readFileSync('resources/native-manifest.json', 'utf8'));
    const corePin = native.components.find(c => c.type === 'core' && c.target === target);
    if (!core || !corePin || createHash('sha256').update(fs.readFileSync(path.join('resources/native', target, core.executable))).digest('hex') !== corePin.sha256) throw new Error('Missing pinned core; run core:fetch and native:build.');
    const helper = native.components.find(c => c.type === 'helper' && c.target === target);
    if (!helper || createHash('sha256').update(fs.readFileSync(helper.file)).digest('hex') !== helper.sha256) throw new Error('Compile the matching helper with npm run native:build first.');
    const resourceRoot = context.electronPlatformName === 'darwin' ? path.join(context.appOutDir, context.packager.appInfo.productFilename + '.app', 'Contents', 'Resources') : path.join(context.appOutDir, 'resources');
    await fs.promises.cp(path.join('resources/native', target), path.join(resourceRoot, 'native', target), { recursive: true });
    const executable = context.electronPlatformName === 'darwin' ? path.join(context.appOutDir, context.packager.appInfo.productFilename + '.app') : path.join(context.appOutDir, context.electronPlatformName === 'win32' ? context.packager.appInfo.productFilename + '.exe' : packageName);
    await flipFuses(executable, { version: FuseVersion.V1, [FuseV1Options.RunAsNode]: false, [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false, [FuseV1Options.EnableNodeCliInspectArguments]: false, [FuseV1Options.OnlyLoadAppFromAsar]: true });
    if (context.electronPlatformName === 'linux') await normalizePermissions(context.appOutDir);
  },
  artifactName: '${productName}-${version}-${os}-${arch}.${ext}',
  win: { target: [{ target: 'nsis', arch: ['x64'] }], icon: 'resources/icon.png', signExts: ['!xray.exe', '!helper.exe', '!wintun.dll'] },
  nsis: { oneClick: false, perMachine: true, allowToChangeInstallationDirectory: false, deleteAppDataOnUninstall: false, include: render('windows/installer.nsh') },
  mac: { target: ['dmg', 'zip'], category: 'public.app-category.utilities', hardenedRuntime: macCertificate, identity: macCertificate ? undefined : '-', minimumSystemVersion: '14.0', icon: 'resources/icon.png', signIgnore: ['native/[^/]+/(xray|helper)$'] },
  linux: { target: [{ target: 'deb', arch: ['x64'] }], executableName: packageName, syncDesktopName: true, category: 'Network', icon: 'resources/icon.png', maintainer: config.name, synopsis: `${config.name} desktop client` },
  deb: { packageName, depends: ['libgtk-3-0', 'libnss3', 'libasound2t64', 'libgbm1', 'libsecret-1-0', 'iproute2', 'nftables', 'systemd-resolved', 'polkitd', 'pkexec', 'dpkg-repack'], afterInstall: 'packaging/linux/after-install.sh', fpm: ['--before-remove=' + render('linux/before-remove.sh')] },
};
