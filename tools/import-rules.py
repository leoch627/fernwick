#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 StarRail Network contributors.
# Conversion of the separately licensed Loyalsoldier rule data, modified 2026-10-31.
"""Reproduce baseline.json using only Python's standard library. No YAML execution."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys


def main():
    # The optional path also supports the rules/source layout shipped inside the DEB.
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('resources/rules')
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    values = {}
    for name in ('direct.txt', 'cncidr.txt'):
        data = (root / 'source' / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest['files']['source/' + name]:
            raise ValueError('Source hash mismatch')
        lines = data.decode('utf-8').rstrip('\n').split('\n')
        if lines.pop(0) != 'payload:':
            raise ValueError('Unexpected source format')
        matches = [re.fullmatch(r"  - '([^']+)'", line) for line in lines]
        if not all(matches):
            raise ValueError('Unsupported payload syntax')
        values[name] = [match.group(1) for match in matches]

    def domain(value):
        # The pinned source already uses ASCII/punycode; reject format changes.
        if len(value) > 253 or not value.isascii() or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part) for part in value.split('.')):
            raise ValueError('Invalid domain')
        return value.lower()

    suffixes = sorted({domain(value[2:]) for value in values['direct.txt'] if value.startswith('+.')})
    exact = sorted({domain(value) for value in values['direct.txt'] if not value.startswith('+.')})
    prefixes = values['cncidr.txt']
    for prefix in prefixes:
        ipaddress.ip_network(prefix)
    if len(suffixes) > 200000 or len(exact) > 200000 or len(prefixes) > 100000:
        raise ValueError('Dataset exceeds client limits')
    rules = dict(schemaVersion=1, directDomains=suffixes, directFullDomains=exact, proxyDomains=[], blockedDomains=[], directIPs=prefixes)
    data = (json.dumps(rules, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > 33554432 or digest != manifest['files']['baseline.json']:
        raise ValueError('Conversion differs from the reviewed pinned baseline')
    (root / 'baseline.json').write_bytes(data)
    print(json.dumps(dict(directSuffixes=len(suffixes), directExact=len(exact), ipPrefixes=len(prefixes), outputSha256=digest)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError):
        sys.exit('Rule source/manifest validation failed; no partial dataset accepted.')
