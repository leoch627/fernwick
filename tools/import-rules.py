#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 StarRail Network contributors.
# Conversion of the separately licensed Loyalsoldier rule data, modified 2026-11-01.
"""Reproduce baseline.json using only Python's standard library. No YAML execution."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys


EXTRA_LISTS = ('directDomains', 'directFullDomains', 'proxyDomains', 'blockedDomains', 'directIPs')


def domain(value):
    # The pinned source already uses ASCII/punycode; reject format changes.
    if not isinstance(value, str) or len(value) > 253 or not value.isascii() or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part) for part in value.split('.')):
        raise ValueError('Invalid domain')
    return value.lower()


def address(value):
    # The form clients accept: a plain address, optionally with a decimal prefix without leading zeros.
    if not isinstance(value, str) or len(value) > 64 or '%' in value:
        raise ValueError('Invalid IP')
    host, slash, prefix = value.partition('/')
    ip = ipaddress.ip_address(host)
    if slash and not (re.fullmatch(r'0|[1-9][0-9]{0,2}', prefix) and int(prefix) <= ip.max_prefixlen):
        raise ValueError('Invalid IP prefix')
    return value


def load_extra(path):
    """Read config/rules-extra.json: operator-maintained additions to the converted upstream lists."""
    def unique(pairs):
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError('Duplicate key')
        return dict(pairs)
    extra = json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=unique)
    if not isinstance(extra, dict) or not set(extra) <= {'comment', *EXTRA_LISTS}:
        raise ValueError('Unknown rules-extra field')
    if not isinstance(extra.get('comment', ''), str):
        raise ValueError('Invalid comment')
    lists = {key: extra.get(key, []) for key in EXTRA_LISTS}
    if not all(isinstance(values, list) for values in lists.values()):
        raise ValueError('Rules-extra fields must be lists')
    lists['directIPs'] = [address(value) for value in lists['directIPs']]
    return {key: values if key == 'directIPs' else [domain(value) for value in values] for key, values in lists.items()}


def convert(sources, extra=None):
    """Convert {'direct.txt': bytes, 'cncidr.txt': bytes} into the client's rules JSON bytes.

    Without extra the output is byte-identical to the pinned baseline. Extra entries are merged in;
    clients match blocked, then proxy, then direct, so proxyDomains overrides the upstream direct list.
    """
    extra = extra or {key: [] for key in EXTRA_LISTS}
    values = {}
    for name in ('direct.txt', 'cncidr.txt'):
        data = sources[name]
        lines = data.decode('utf-8').rstrip('\n').split('\n')
        if lines.pop(0) != 'payload:':
            raise ValueError('Unexpected source format')
        matches = [re.fullmatch(r"  - '([^']+)'", line) for line in lines]
        if not all(matches):
            raise ValueError('Unsupported payload syntax')
        values[name] = [match.group(1) for match in matches]

    suffixes = sorted({domain(value[2:]) for value in values['direct.txt'] if value.startswith('+.')} | set(extra['directDomains']))
    exact = sorted({domain(value) for value in values['direct.txt'] if not value.startswith('+.')} | set(extra['directFullDomains']))
    prefixes = values['cncidr.txt']
    for prefix in prefixes:
        ipaddress.ip_network(prefix)
    prefixes = prefixes + sorted(set(extra['directIPs']) - set(prefixes))
    proxy, blocked = sorted(set(extra['proxyDomains'])), sorted(set(extra['blockedDomains']))
    if len(suffixes) > 200000 or len(exact) > 200000 or len(prefixes) > 100000 or len(proxy) > 100000 or len(blocked) > 100000:
        raise ValueError('Dataset exceeds client limits')
    rules = dict(schemaVersion=1, directDomains=suffixes, directFullDomains=exact, proxyDomains=proxy, blockedDomains=blocked, directIPs=prefixes)
    data = (json.dumps(rules, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    if len(data) > 33554432:
        raise ValueError('Dataset exceeds client limits')
    return data, dict(directSuffixes=len(suffixes), directExact=len(exact), ipPrefixes=len(prefixes), proxyDomains=len(proxy), blockedDomains=len(blocked), outputSha256=hashlib.sha256(data).hexdigest())


def main():
    # --convert <direct.txt> <cncidr.txt> <out.json> [rules-extra.json]: publish newer upstream data for remote rule updates.
    if len(sys.argv) in (5, 6) and sys.argv[1] == '--convert':
        extra = load_extra(sys.argv[5]) if len(sys.argv) == 6 else None
        data, stats = convert({'direct.txt': Path(sys.argv[2]).read_bytes(), 'cncidr.txt': Path(sys.argv[3]).read_bytes()}, extra)
        Path(sys.argv[4]).write_bytes(data)
        print(json.dumps(dict(stats, bytes=len(data))))
        return
    # The optional path also supports the rules/source layout shipped inside the DEB.
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('resources/rules')
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    sources = {}
    for name in ('direct.txt', 'cncidr.txt'):
        sources[name] = (root / 'source' / name).read_bytes()
        if hashlib.sha256(sources[name]).hexdigest() != manifest['files']['source/' + name]:
            raise ValueError('Source hash mismatch')
    data, stats = convert(sources)
    if stats['outputSha256'] != manifest['files']['baseline.json']:
        raise ValueError('Conversion differs from the reviewed pinned baseline')
    (root / 'baseline.json').write_bytes(data)
    print(json.dumps(stats))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError):
        sys.exit('Rule source/manifest validation failed; no partial dataset accepted.')
