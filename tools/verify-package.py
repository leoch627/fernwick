#!/usr/bin/env python3
"""Inspect the Linux development DEB without installing it or running maintainer scripts."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

package = Path(sys.argv[1]) if len(sys.argv) > 1 else next(Path('release').glob('*.deb'))
metadata = subprocess.check_output(['dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}', str(package)], text=True).splitlines()
assert metadata == ['starrail-network-dev', '0.1.0', 'amd64'], metadata
lock = json.loads(Path('resources/core-lock.json').read_text())
core = next(asset for asset in lock['assets'] if asset['target'] == 'linux-x64')
prefix = './opt/StarRail Network Dev/'
resource = prefix + 'resources/'
expected = {resource + 'native/linux-x64/' + core['executable']: core['executableSha256'], resource + 'native/linux-x64/LICENSE': core['licenseSha256']}
manifest = json.loads(Path('resources/rules/manifest.json').read_text())
expected.update({resource + 'rules/' + name: value for name, value in manifest['files'].items()})
required = {prefix + 'starrail-network-dev', resource + 'app.asar', prefix + 'LICENSE.electron.txt', prefix + 'LICENSES.chromium.html', resource + 'THIRD_PARTY_NOTICES.md', resource + 'rules/import-rules.py'}
seen = set()
process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(package)], stdout=subprocess.PIPE)
try:
    with tarfile.open(fileobj=process.stdout, mode='r|*') as archive:
        for member in archive:
            if member.isfile() or member.isdir():
                assert not member.mode & 0o002, 'World-writable entry: ' + member.name
            if member.isfile():
                if member.name in expected:
                    digest = hashlib.sha256()
                    with archive.extractfile(member) as stream:
                        while chunk := stream.read(1024 * 1024):
                            digest.update(chunk)
                    assert digest.hexdigest() == expected[member.name], 'Hash mismatch: ' + member.name
                    seen.add(member.name)
                if member.name in required:
                    seen.add(member.name)
                if member.name == prefix + 'starrail-network-dev':
                    assert member.mode == 0o755
                if member.name == resource + 'app.asar':
                    assert member.mode == 0o644
    assert process.wait() == 0
    assert required | set(expected) <= seen, 'Missing package entries: ' + repr((required | set(expected)) - seen)
finally:
    if process.poll() is None:
        process.terminate()
        process.wait()
print('DEB inspection passed: metadata, executable/data permissions, no world-writable files, exact core/rule/source/license hashes and notices. Package was not installed.')
