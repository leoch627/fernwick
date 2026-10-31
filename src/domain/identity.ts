import { join, dirname } from 'node:path';
import type { BuildConfig } from '../shared/schema';
// Mirrors native/helper/names.go: system names derive from the stable productId, never the display name.
export const productIdPattern = /^[a-z][a-z0-9-]{1,38}[a-z0-9]$/;
export const appIdPattern = /^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$/;
// Display names reach installers, plists, unit files and file names; keep them inert there.
export const displayNamePattern = /^[^\u0000-\u001f"'`$\\<>&/:*?|]{1,64}$/;
export const tunNames = { darwin: 'utun50', win32: 'ProxyTun', linux: 'vbtun0' } as const;
export const helperLabel = (build: BuildConfig) => `${build.appId}.helper`;
export function helperSocket(build: BuildConfig, platform = process.platform) {
  if (platform === 'win32') return `\\\\.\\pipe\\${build.productId}.helper.v1`;
  return platform === 'darwin' ? `/var/run/${build.productId}/helper.sock` : `/run/${build.productId}/helper.sock`;
}
/** Directory holding the helper's server-public.pem. On Windows it sits beside the per-machine app directory. */
export function helperRoot(build: BuildConfig, appRoot: string, platform = process.platform) {
  if (platform === 'win32') return join(dirname(appRoot), `${build.productId}-service`);
  return platform === 'darwin' ? `/Library/PrivilegedHelperTools/${helperLabel(build)}` : `/usr/lib/${build.productId}`;
}
