import { spawn } from 'node:child_process';
import { createServer } from 'vite';
const executable = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const build = spawn(executable, ['run', 'build'], { stdio: 'inherit', shell: process.platform === 'win32' });
build.once('exit', async code => {
  if (code) { process.exitCode = code; return; }
  const server = await createServer(); await server.listen();
  const electron = (await import('electron')).default as unknown as string;
  const child = spawn(electron, ['.', ...(process.argv.includes('--demo') ? ['--demo'] : [])], { stdio: 'inherit', env: { ...process.env, STARRAIL_DEV_UI: '1' } });
  const stop = () => { child.kill(); void server.close(); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  child.once('exit', code => { void server.close(); process.exitCode = code ?? 0; });
});
