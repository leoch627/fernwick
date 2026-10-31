#!/usr/bin/env python3
"""Sign native executables before application packaging, then pin the resulting bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=['core', 'helper'])
    parser.add_argument('target', choices=['win32-x64', 'darwin-x64', 'darwin-arm64'])
    args = parser.parse_args()
    platform = args.target.split('-')[0]
    if sys.platform != platform: raise RuntimeError('Run native signing on the target operating system')
    identity = os.environ['STARRAIL_NATIVE_SIGN_IDENTITY']
    build = json.loads((ROOT/os.environ.get('STARRAIL_BUILD_CONFIG', 'config/development.json')).read_text(encoding='utf-8'))
    if build['environment'] == 'production' and identity == '-': raise RuntimeError('Production requires a real signing identity')
    extension = '.exe' if platform == 'win32' else ''
    path = ROOT/'resources/native'/args.target/(('xray' if args.stage == 'core' else 'helper') + extension)
    lock = json.loads((ROOT/'resources/core-lock.json').read_text(encoding='utf-8'))
    asset = next(a for a in lock['assets'] if a['target'] == args.target)
    if args.stage == 'core' and digest(path) != asset['executableSha256']: raise RuntimeError('Fetch the exact upstream core again before signing')
    if platform == 'darwin':
        command = ['/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime']
        if identity != '-': command += ['--timestamp']
        subprocess.run(command+[str(path)], check=True)
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(path)], check=True)
    else:
        tool = os.environ.get('STARRAIL_SIGNTOOL', 'signtool.exe')
        subprocess.run([tool, 'sign', '/sha1', identity, '/fd', 'SHA256', '/tr', os.environ.get('STARRAIL_TIMESTAMP_URL', 'http://timestamp.digicert.com'), '/td', 'SHA256', str(path)], check=True)
        subprocess.run([tool, 'verify', '/pa', str(path)], check=True)
    if args.stage == 'core':
        record = ROOT/'resources/native-signatures.json'
        values = json.loads(record.read_text(encoding='utf-8')) if record.exists() else {}
        values[args.target] = {'upstreamSha256': asset['executableSha256'], 'signedSha256': digest(path), 'identity': identity}
        record.write_text(json.dumps(values, indent=2)+'\n')
    else:
        record = ROOT/'resources/native-manifest.json'; value = json.loads(record.read_text(encoding='utf-8'))
        item = next(c for c in value['components'] if c['type'] == 'helper' and c['target'] == args.target)
        item['sha256'] = digest(path); item['signatureIdentity'] = identity
        record.write_text(json.dumps(value, indent=2)+'\n')
if __name__ == '__main__': main()
