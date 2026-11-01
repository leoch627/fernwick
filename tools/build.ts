import { build as buildUI } from 'vite';
import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { validateBuild } from '../src/domain/trust';
import { strictJson } from '../src/domain/json';
import { ContractSchema } from '../src/services/panel';
import { RulesSchema } from '../src/domain/compiler';
import { createHash } from 'node:crypto';
async function main() {
  const config = validateBuild(strictJson(await readFile(process.env.STARRAIL_BUILD_CONFIG ?? 'config/development.json', 'utf8')));
  const contract = ContractSchema.parse(strictJson(await readFile('config/adapter-contract.json', 'utf8')));
  const ruleManifest = strictJson(await readFile('resources/rules/manifest.json', 'utf8')) as { 'baseline.json': string };
  if (createHash('sha256').update(await readFile('resources/rules/baseline.json')).digest('hex') !== ruleManifest['baseline.json']) throw new Error('Rule baseline does not match resources/rules/manifest.json');
  RulesSchema.parse(strictJson(await readFile('resources/rules/baseline.json', 'utf8'), 33554432));
  await mkdir('desktop/assets/rules', { recursive: true });
  await mkdir('dist/rules', { recursive: true });
  await buildUI({ configFile: resolve('vite.config.ts') });
  const { version } = JSON.parse(await readFile('package.json', 'utf8')) as { version: string };
  for (const destination of ['desktop/assets', 'dist']) {
    await writeFile(`${destination}/build-config.json`, JSON.stringify(config, null, 2));
    await writeFile(`${destination}/adapter-contract.json`, JSON.stringify(contract, null, 2));
    await writeFile(`${destination}/version.txt`, version + '\n');
    await copyFile('resources/icon.png', `${destination}/icon.png`);
    await copyFile('resources/native-manifest.json', `${destination}/native-manifest.json`);
    await copyFile('resources/rules/baseline.json', `${destination}/rules/baseline.json`);
  }
  console.log(`Built ${config.name} (${config.environment}); platform support is governed by support-matrix.json.`);
}
void main().catch(error => { console.error(`Build failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
