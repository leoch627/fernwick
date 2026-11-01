#!/usr/bin/env python3
"""Verify Wails package contents and hashes without installing or running them."""
import argparse
import importlib.util
import os
from pathlib import Path
import hashlib
import plistlib
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('packager', ROOT / 'tools/package.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


def inspect_tree(path, target, config, manifest):
    if target.startswith('darwin-'):
        apps = list(path.glob('*.app')) if path.suffix != '.app' else [path]
        if len(apps) != 1:
            raise ValueError('Expected exactly one application bundle')
        app = apps[0]
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        if info['CFBundleIdentifier'] != config['appId'] or info['LSMinimumSystemVersion'] != packager.MACOS_MINIMUM:
            raise ValueError('Incorrect bundle metadata')
        executable = app / 'Contents/MacOS' / packager.executable_name(config, target)
        resources = app / 'Contents/Resources'
    else:
        executable = path / packager.executable_name(config, target)
        resources = path / 'resources'
    if not executable.is_file() or executable.stat().st_size == 0:
        raise ValueError('Missing application executable')
    packager.verify_resources(resources, target, manifest)
    if (resources / 'app.asar').exists():
        raise ValueError('Obsolete Electron archive in Wails package')
    # Windows reports every directory as mode 777: NTFS permissions are ACLs, which
    # the installer sets under Program Files. The bits only mean something elsewhere.
    if os.name == 'nt':
        return
    for item in path.rglob('*'):
        if not item.is_symlink() and item.stat().st_mode & 0o002:
            raise ValueError('World-writable package entry: ' + str(item))


def inspect_deb(package, config, manifest):
    version = packager.read_json(ROOT / 'package.json')['version']
    metadata = subprocess.check_output(['dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}\n${Depends}', str(package)], text=True).splitlines()
    if metadata[:3] != [config['productId'], version, 'amd64']:
        raise ValueError('Incorrect Debian metadata: ' + repr(metadata))
    if any(dep not in metadata[3] for dep in packager.LINUX_DEPENDS):
        raise ValueError('Missing GTK/WebKit or network recovery dependency')
    prefix = './opt/' + packager.product_name(config) + '/'
    resources = prefix + 'resources/'
    expected = {resources + name: digest for name, digest in packager.expected_resources('linux-x64', manifest).items()}
    required = {prefix + config['productId'], resources + 'native-manifest.json', resources + 'core-lock.json', resources + 'THIRD_PARTY_NOTICES.md', resources + 'rules/manifest.json'}
    seen = set()
    process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(package)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|*') as archive:
            for member in archive:
                if member.isfile() or member.isdir():
                    if member.mode & 0o002 or member.uid != 0 or member.gid != 0:
                        raise ValueError('Unsafe ownership or permissions: ' + member.name)
                if member.name.endswith('/app.asar') or 'chrome-sandbox' in member.name:
                    raise ValueError('Obsolete Electron resource: ' + member.name)
                if member.isfile():
                    if member.name in expected:
                        digest = hashlib.sha256()
                        with archive.extractfile(member) as stream:
                            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                                digest.update(chunk)
                        if digest.hexdigest() != expected[member.name]:
                            raise ValueError('Hash mismatch: ' + member.name)
                        seen.add(member.name)
                    if member.name in required:
                        seen.add(member.name)
                    if member.name == prefix + config['productId'] and member.mode != 0o755:
                        raise ValueError('Application is not executable')
        if process.wait() != 0:
            raise ValueError('dpkg-deb failed')
        missing = (required | set(expected)) - seen
        if missing:
            raise ValueError('Missing entries: ' + repr(missing))
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--target', choices=list(packager.TARGETS))
    args = parser.parse_args()
    config = packager.read_json(ROOT / 'dist/build-config.json')
    manifest = packager.read_json(ROOT / 'resources/native-manifest.json')
    if args.path.suffix == '.deb':
        inspect_deb(args.path, config, manifest)
    elif args.path.is_dir() and args.target:
        inspect_tree(args.path, args.target, config, manifest)
    else:
        raise ValueError('Use a .deb file or an unpacked directory with --target')
    print('Package inspection passed: metadata, executable permissions, exact core/helper/rule/license hashes and notices. Package was not installed.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Package verification failed: {error}')
