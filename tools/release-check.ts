import { readFile } from 'node:fs/promises';
import { validateBuild } from '../src/domain/trust';
import { strictJson } from '../src/domain/json';
// Runs before packaging a production build. Per-target core/helper hashes are checked in afterPack.
// Checks dist/build-config.json by default: the configuration that is actually packaged, not a file
// that may or may not have been passed to npm run build.
void (async () => {
  const path = process.argv[2] ?? 'dist/build-config.json';
  try {
    const config = validateBuild(strictJson(await readFile(path, 'utf8')));
    if (config.environment !== 'production') throw new Error('not a production configuration');
    const matrix = strictJson(await readFile('support-matrix.json', 'utf8')) as { targets: { id: string; status: string }[] };
    const untested = matrix.targets.filter(t => t.status !== 'passed').map(t => t.id);
    if (untested.length) console.warn(`::warning::Platforms without recorded acceptance: ${untested.join(', ')}. See support-matrix.json.`);
    console.log(`Release configuration verified: ${config.name} (${config.productId}) → ${config.updateFeedUrls.join(', ')}`);
  } catch { console.error(`RELEASE BLOCKED: ${path} is not a valid production configuration. Generate one with npm run brand and build with STARRAIL_BUILD_CONFIG pointing at it.`); process.exitCode = 1; }
})();
