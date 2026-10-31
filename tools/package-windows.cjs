// Use electron-builder's own static NSIS uninstaller extraction on Linux.
// This generates the installer without executing Windows programs or installing the app.
const path = require('node:path');
const { build, Platform, Arch } = require('electron-builder');
if (process.platform === 'linux') {
  const { WineVmManager } = require('app-builder-lib/out/vm/WineVm');
  const { UninstallerReader } = require('app-builder-lib/out/targets/nsis/nsisUtil');
  const original = WineVmManager.prototype.exec;
  WineVmManager.prototype.exec = function (file, args, options) {
    if (options?.env?.__COMPAT_LAYER === 'RunAsInvoker' && args.length === 0 && file.endsWith('.exe')) {
      const output = path.join(path.dirname(file), path.basename(file, 'exe') + '__uninstaller.exe');
      return UninstallerReader.exec(file, output).then(() => '');
    }
    return original.call(this, file, args, options);
  };
}
build({ targets: Platform.WINDOWS.createTarget(['nsis'], Arch.x64), config: { ...require('../electron-builder.cjs'), directories: { output: 'release/windows', buildResources: 'resources' } } }).catch(error => { console.error(error.message); process.exitCode = 1; });
