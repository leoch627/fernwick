#!/usr/bin/env python3
"""Fetch only the reviewed, hash-pinned upstream release. No installer execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', choices=['linux-x64', 'win32-x64', 'darwin-x64', 'darwin-arm64'])
    parser.add_argument('--archive', type=Path, help='Use an already downloaded archive; hashes are still checked.')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'resources/core-lock.json').read_text(encoding='utf-8'))
    asset = next(x for x in lock['assets'] if x['target'] == args.target)
    destination = ROOT / 'resources/native' / args.target
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='core-', dir=ROOT / 'work') as tmp:
        archive = args.archive or Path(tmp) / 'core.zip'
        if not args.archive:
            with urllib.request.urlopen(asset['url'], timeout=30) as response, archive.open('wb') as output:
                size = 0
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > asset['bytes']:
                        raise ValueError('Upstream archive is larger than the pinned release')
                    output.write(chunk)
        data = archive.read_bytes()
        if len(data) != asset['bytes'] or hashlib.sha256(data).hexdigest() != asset['sha256']:
            raise ValueError('Upstream archive hash/size mismatch')
        with zipfile.ZipFile(archive) as package:
            for name in (asset['executable'], 'LICENSE', *asset.get('extras', {})):
                matches = [x for x in package.infolist() if x.filename == name]
                if len(matches) != 1 or matches[0].file_size > 100 * 1024 * 1024:
                    raise ValueError('Unexpected archive layout')
                content = package.read(matches[0])
                digest = hashlib.sha256(content).hexdigest()
                expected = asset.get('executableSha256') if name == asset['executable'] else asset.get('licenseSha256') if name == 'LICENSE' else asset['extras'][name]
                if not expected or digest != expected:
                    raise ValueError('Extracted file hash mismatch')
                temporary = Path(tmp) / name
                temporary.write_bytes(content)
                temporary.chmod(0o755 if name == asset['executable'] else 0o644)
                os.replace(temporary, destination / name)
                print(f'{args.target} {name} sha256:{digest}')

if __name__ == '__main__':
    (ROOT / 'work').mkdir(exist_ok=True)
    main()
