import { spawn } from 'node:child_process';
import { createServer } from 'vite';

async function develop() {
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const build = spawn(npm, ['run', 'build'], { stdio: 'inherit', shell: process.platform === 'win32' });
  const code = await new Promise<number>((resolve, reject) => { build.once('error', reject); build.once('exit', code => resolve(code ?? 1)); });
  if (code) { process.exitCode = code; return; }
  const server = await createServer();
  await server.listen();
  const child = spawn(process.env.STARRAIL_GO ?? 'go', ['run', '-tags', 'gtk3', '.', ...(process.argv.includes('--demo') ? ['--demo'] : [])], {
    cwd: 'desktop', stdio: 'inherit', env: { ...process.env, STARRAIL_DEV_UI: '1' },
  });
  const stop = () => { child.kill(); void server.close(); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  child.once('error', error => { console.error(error.message); process.exitCode = 1; void server.close(); });
  child.once('exit', code => { void server.close(); process.exitCode = code ?? 0; });
}
void develop().catch(error => { console.error(error); process.exitCode = 1; });
