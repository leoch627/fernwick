import { build as bundle } from 'esbuild';
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
  const ruleManifest = strictJson(await readFile('resources/rules/manifest.json', 'utf8')) as { files: Record<string, string> };
  for (const [file, hash] of Object.entries(ruleManifest.files)) { if (!/^source\/(direct\.txt|cncidr\.txt|LICENSE)$|^baseline\.json$/.test(file) || createHash('sha256').update(await readFile(`resources/rules/${file}`)).digest('hex') !== hash) throw new Error('Rule inventory mismatch'); }
  RulesSchema.parse(strictJson(await readFile('resources/rules/baseline.json', 'utf8'), 33554432));
  await mkdir('dist/main', { recursive: true });
  await bundle({ entryPoints: { main: 'src/main/main.ts', preload: 'src/main/preload.ts', 'parse-worker': 'src/services/parse-worker.ts' }, outdir: 'dist/main', outExtension: { '.js': '.cjs' }, bundle: true, platform: 'node', format: 'cjs', target: 'node24', external: ['electron'], sourcemap: false, minify: false });
  await buildUI({ configFile: resolve('vite.config.ts') });
  await writeFile('dist/build-config.json', JSON.stringify(config, null, 2));
  await writeFile('dist/adapter-contract.json', JSON.stringify(contract, null, 2));
  await copyFile('resources/icon.png', 'dist/icon.png');
  await copyFile('resources/native-manifest.json', 'dist/native-manifest.json');
  await mkdir('dist/rules', { recursive: true }); await copyFile('resources/rules/baseline.json', 'dist/rules/baseline.json');
  console.log(`Built ${config.name} (${config.environment}); platform support is governed by support-matrix.json.`);
}
void main().catch(error => { console.error(`Build failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
