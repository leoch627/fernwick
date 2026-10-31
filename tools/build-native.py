#!/usr/bin/env python3
"""Compile immutable helper executables. This command does not run them or run tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', action='append', choices=['linux-x64', 'win32-x64', 'darwin-x64', 'darwin-arm64'])
    args = parser.parse_args()
    config = json.loads((ROOT / os.environ.get('STARRAIL_BUILD_CONFIG', 'config/development.json')).read_text(encoding='utf-8'))
    lock = json.loads((ROOT / 'resources/core-lock.json').read_text(encoding='utf-8'))
    signatures_path = ROOT / 'resources/native-signatures.json'
    signatures = json.loads(signatures_path.read_text(encoding='utf-8')) if signatures_path.exists() else {}
    core_hashes = {}
    for asset in lock['assets']:
        expected = asset['executableSha256']; signed = signatures.get(asset['target'])
        if signed:
            if signed['upstreamSha256'] != expected: raise ValueError('Signing record is for a different upstream core')
            expected = signed['signedSha256']
        path = ROOT / 'resources/native' / asset['target'] / asset['executable']
        if path.exists() and sha(path) != expected: raise ValueError('Native core has changed outside the pinned signing pipeline')
        core_hashes[asset['target']] = expected
    origins = sorted(set([item['baseUrl'].rstrip('/') for item in config['apiEndpoints']] + config['trustedSubscriptionOrigins'] + config['trustedResourceOrigins'] + [__import__('urllib.parse', fromlist=['urlsplit']).urlsplit(u)._replace(path='', query='', fragment='').geturl() for u in config['policyUrls'] + config['updateFeedUrls']]))
    # Must match electron-builder.cjs: productName for Windows/macOS, productId for the Linux executable.
    product = config['name'] + (' Dev' if config['environment'] == 'test' else '')
    names = {'linux-x64': config['productId'], 'win32-x64': product + '.exe', 'darwin-x64': product, 'darwin-arm64': product}
    version = json.loads((ROOT / 'package.json').read_text(encoding='utf-8'))['version']
    native = {'productId': config['productId'], 'displayName': product, 'helperLabel': config['appId'] + '.helper', 'environment': config['environment'], 'channel': config['channel'], 'version': version, 'coreVersion': lock['version'], 'coreHashes': {a['target']: a['executableSha256'] for a in lock['assets']}, 'controlOrigins': origins, 'controlHosts': sorted(set(__import__('urllib.parse', fromlist=['urlsplit']).urlsplit(u).hostname for u in origins)), 'healthTargets': config['healthTargets'], 'updateKeys': config['updateKeys'], 'trustedUpdateOrigins': config['trustedUpdateOrigins'], 'appExecutableName': names['linux-x64'], 'appExecutableNames': names, 'nativeHashes': lock['assets'][-1].get('extras', {})}
    native['coreHashes'] = core_hashes
    digest = hashlib.sha256(json.dumps(native, sort_keys=True).encode())
    for path in sorted((ROOT / 'native/helper').glob('*')):
        if path.suffix == '.go' or path.name in ('go.mod', 'go.sum'): digest.update(path.name.encode() + path.read_bytes())
    native['buildId'] = digest.hexdigest()
    (ROOT / 'native/helper/build.json').write_text(json.dumps(native, indent=2) + '\n')
    targets = args.target or list(names)
    previous = json.loads((ROOT / 'resources/native-manifest.json').read_text(encoding='utf-8'))
    components = [c for c in previous['components'] if c['type'] == 'core' or (c['target'] not in targets and previous.get('buildId') == native['buildId'])]
    for c in components:
        if c['type'] == 'core': c['sha256'] = core_hashes[c['target']]
    go = os.environ.get('STARRAIL_GO', 'go')
    for target in targets:
        platform, arch = target.split('-'); name = 'helper.exe' if platform == 'win32' else 'helper'
        output = ROOT / 'resources/native' / target / name
        output.parent.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, 'CGO_ENABLED': '0', 'GOOS': 'windows' if platform == 'win32' else platform, 'GOARCH': 'amd64' if arch == 'x64' else arch, 'GOTOOLCHAIN': 'local'}
        subprocess.run([go, 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', str(output), '.'], cwd=ROOT/'native/helper', env=env, check=True)
        output.chmod(0o755)
        components.append({'type': 'helper', 'target': target, 'file': str(output.relative_to(ROOT)), 'sha256': sha(output)})
        print(f'Compiled {target}: {output.name}', flush=True)
    for a in lock['assets']:
        for name, expected in a.get('extras', {}).items():
            path = ROOT / 'resources/native' / a['target'] / name
            if path.exists() and sha(path) != expected: raise ValueError('Native dependency hash mismatch')
    manifest = {'schemaVersion': 1, 'verified': False, 'buildId': native['buildId'], 'core': 'Xray-core', 'coreVersion': lock['version'], 'helperProtocol': 1, 'components': components, 'reason': 'Native functionality implemented and compiled. Runtime and platform acceptance tests are deferred at the user’s request.'}
    (ROOT / 'resources/native-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
if __name__ == '__main__': main()
