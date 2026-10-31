import { readFile } from 'node:fs/promises';
import { validateBuild } from '../src/domain/trust';
import { strictJson } from '../src/domain/json';
import { assert } from '../src/shared/errors';
const required = ['win32-x64', 'darwin-arm64', 'darwin-x64', 'linux-x64'];
void (async () => {
  try {
    const config = validateBuild(strictJson(await readFile(process.env.STARRAIL_BUILD_CONFIG ?? 'config/production.pending.json', 'utf8'))); assert(config.environment === 'production');
    const matrix = strictJson(await readFile('support-matrix.json', 'utf8')) as { targets: { id: string; status: string; evidence: string[] }[] };
    for (const id of required) { const target = matrix.targets.find(t => t.id === id); assert(target?.status === 'passed' && target.evidence.length > 0); for (const path of target.evidence) await readFile(path); }
    const native = strictJson(await readFile('resources/native-manifest.json', 'utf8')) as { verified: boolean; components: { file: string; sha256: string }[] };
    assert(native.verified && native.components.length >= 8);
    const { createHash } = await import('node:crypto'); for (const component of native.components) assert(createHash('sha256').update(await readFile(component.file)).digest('hex') === component.sha256);
    console.log('Release prerequisite files verified. Platform signatures and installation records remain part of release approval.');
  } catch { console.error('RELEASE BLOCKED: production configuration, real deployment, signed core/helper sets and four-target evidence are not complete. See docs/DELIVERY.md.'); process.exitCode = 1; }
})();
