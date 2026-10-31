import { readFile } from 'node:fs/promises';
import { validateBuild } from '../src/domain/trust';
import { strictJson } from '../src/domain/json';
void (async () => {
  try { const config = validateBuild(strictJson(await readFile(process.argv[2] ?? process.env.STARRAIL_BUILD_CONFIG ?? 'config/development.json', 'utf8'))); console.log(`Configuration valid: ${config.productId} / ${config.environment}. This is not a deployment validation.`); }
  catch { console.error('Configuration rejected: check endpoints, keys, environment and deployment evidence.'); process.exitCode = 1; }
})();
