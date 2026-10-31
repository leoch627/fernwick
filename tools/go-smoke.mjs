import { spawnSync } from 'node:child_process';
const kind = process.argv[2];
const smoke = { core: ['STARRAIL_CORE_SMOKE', 'TestCoreSmoke'], download: ['STARRAIL_DOWNLOAD_SMOKE', 'TestDownloadSmoke'] }[kind];
if (!smoke) throw new Error('Usage: node tools/go-smoke.mjs core|download');
const result = spawnSync(process.env.STARRAIL_GO || 'go', ['test', './core', '-run', `^${smoke[1]}$`, '-count=1', '-v'], {
  cwd: new URL('../desktop/', import.meta.url), stdio: 'inherit', env: { ...process.env, [smoke[0]]: '1' },
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
