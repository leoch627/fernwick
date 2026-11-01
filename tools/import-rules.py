#!/usr/bin/env python3
"""Build the client's routing rules from v2fly geosite / geoip data. Standard library only.

Section order and targets mirror the operator's Mihomo template (~/dev/rules/custom.clash.yaml)
with every selectable group fixed to its default, because desktop users only pick one node:

  private → direct, ads → block, geolocation-!cn@cn → direct, AI → ai (never HK/MO nodes),
  telegram/youtube/netflix → proxy, steam → direct, github/google/microsoft → proxy,
  apple/icloud/bilibili → direct, entertainment → proxy, geolocation-cn → direct,
  geolocation-!cn → proxy, tld-cn → direct, then private and CN addresses → direct.

A domain that an earlier section already covers is dropped, so section order is priority.
config/rules-extra.json entries go first: blocked, then proxy, then direct.

  python3 tools/import-rules.py build [--geosite dlc.dat --geoip geoip.dat]   rebuild the pinned baseline
  python3 tools/import-rules.py check [--geosite dlc.dat --geoip geoip.dat]   verify the committed baseline
  python3 tools/import-rules.py latest OUT [rules-extra.json]                newest upstream data, for remote updates
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'resources/rules'
LATEST = {
    'geosite': 'https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat',
    'geoip': 'https://github.com/v2fly/geoip/releases/latest/download/geoip-only-cn-private.dat',
}
SECTIONS = [
    ('direct', ['private']),
    ('block', ['category-ads-all', 'geolocation-cn@ads']),
    ('direct', ['geolocation-!cn@cn']),
    ('ai', ['category-ai-!cn']),
    ('proxy', ['telegram', 'youtube', 'netflix']),
    ('direct', ['steam']),
    ('proxy', ['github', 'google', 'microsoft']),
    ('direct', ['apple', 'icloud', 'bilibili']),
    ('proxy', ['category-entertainment']),
    ('direct', ['geolocation-cn']),
    ('proxy', ['geolocation-!cn']),
    ('direct', ['tld-cn']),
]
GEOIP_DIRECT = ['private', 'cn']
EXTRA_LISTS = ('directDomains', 'directFullDomains', 'proxyDomains', 'blockedDomains', 'directIPs')
SITE_TYPES = {0: 'keyword', 1: 'regexp', 2: 'domain', 3: 'full'}
TYPE_ORDER = {'domain': 0, 'full': 1, 'keyword': 2, 'regexp': 3}
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
KEYWORD = re.compile(r'[a-z0-9.-]{1,253}')
# Xray compiles these with Go's RE2: no lookaround, backreferences or possessive forms.
REGEXP_UNSUPPORTED = re.compile(r'\(\?[=!<]|\\[1-9]|[*+?}]\+')
MAX_DOMAINS, MAX_IPS = 200000, 100000


def _varint(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _fields(buf):
    i, n = 0, len(buf)
    while i < n:
        key, i = _varint(buf, i)
        num, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire == 2:
            length, i = _varint(buf, i)
            value, i = buf[i:i + length], i + length
        elif wire == 1:
            value, i = buf[i:i + 8], i + 8
        elif wire == 5:
            value, i = buf[i:i + 4], i + 4
        else:
            raise ValueError(f'unsupported wire type {wire}')
        yield num, value


def load_geosite(data):
    """{category: [(type, value, attrs)]} from a v2fly GeoSiteList."""
    sites = {}
    for num, entry in _fields(data):
        if num != 1:
            continue
        code, domains = '', []
        for field, value in _fields(entry):
            if field == 1:
                code = value.decode().lower()
            elif field == 2:
                typ, text, attrs = 0, '', []
                for dfield, dvalue in _fields(value):
                    if dfield == 1:
                        typ = dvalue
                    elif dfield == 2:
                        text = dvalue.decode()
                    elif dfield == 3:
                        attrs += [a.decode() for afield, a in _fields(dvalue) if afield == 1]
                domains.append((SITE_TYPES[typ], text, frozenset(attrs)))
        sites[code] = domains
    return sites


def load_geoip(data):
    """{category: [ip_network]} from a v2fly GeoIPList."""
    ips = {}
    for num, entry in _fields(data):
        if num != 1:
            continue
        code, networks = '', []
        for field, value in _fields(entry):
            if field == 1:
                code = value.decode().lower()
            elif field == 2:
                ip, prefix = b'', 0
                for cfield, cvalue in _fields(value):
                    if cfield == 1:
                        ip = cvalue
                    elif cfield == 2:
                        prefix = cvalue
                networks.append(ipaddress.ip_network((ipaddress.ip_address(ip), prefix), strict=False))
        ips[code] = networks
    return ips


def select(sites, spec):
    """'name', 'name@attr' (only entries with attr) or 'name@-attr' (without attr), stackable."""
    name, *attrs = spec.lower().split('@')
    if name not in sites:
        raise KeyError(f'geosite has no category {name!r}')
    domains = sites[name]
    for attr in attrs:
        if attr.startswith('-'):
            domains = [d for d in domains if attr[1:] not in d[2]]
        else:
            domains = [d for d in domains if attr in d[2]]
    return domains


def valid(typ, value):
    if typ in ('domain', 'full'):
        return 0 < len(value) <= 253 and all(LABEL.fullmatch(label) for label in value.split('.'))
    if typ == 'keyword':
        return bool(KEYWORD.fullmatch(value))
    if not value.isascii() or not value.isprintable() or len(value) > 512 or REGEXP_UNSUPPORTED.search(value):
        return False
    try:
        re.compile(value)
    except re.error:
        return False
    return True


class Coverage:
    """Domains already matched by an earlier rule, so later sections can drop them."""

    def __init__(self):
        self.suffixes, self.fulls, self.keywords, self.regexps = set(), set(), [], set()

    def add(self, typ, value):
        if typ == 'domain':
            self.suffixes.add(value)
        elif typ == 'full':
            self.fulls.add(value)
        elif typ == 'keyword':
            self.keywords.append(value)
        else:
            self.regexps.add(value)

    def covers(self, typ, value, strict=False):
        """strict ignores the entry itself, for deduplicating inside one section."""
        if typ == 'regexp':
            return not strict and value in self.regexps
        if any(k in value for k in self.keywords if not (strict and typ == 'keyword' and k == value)):
            return True
        if typ == 'keyword':
            return False
        if typ == 'full' and value in self.fulls and not strict:
            return True
        labels = value.split('.')
        start = 1 if strict and typ == 'domain' else 0
        return any('.'.join(labels[i:]) in self.suffixes for i in range(start, len(labels)))


def section(entries, coverage):
    entries = list(dict.fromkeys(entries))
    kept = [e for e in entries if not coverage.covers(*e)]
    local = Coverage()
    for e in kept:
        local.add(*e)
    final = sorted((e for e in kept if not local.covers(*e, strict=True)), key=lambda e: (TYPE_ORDER[e[0]], e[1]))
    for e in final:
        coverage.add(*e)
    return [f'{typ}:{value}' for typ, value in final]


def load_extra(path):
    """config/rules-extra.json: operator additions that take priority over the generated sections."""
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
    if not all(isinstance(values, list) and all(isinstance(v, str) for v in values) for values in lists.values()):
        raise ValueError('Rules-extra fields must be lists of strings')
    for key, values in lists.items():
        if key == 'directIPs':
            lists[key] = [str(ipaddress.ip_network(v, strict=False)) for v in values]
        else:
            lists[key] = [v.lower() for v in values]
            if not all(valid('domain', v) for v in lists[key]):
                raise ValueError(f'Invalid domain in {key}')
    return lists


def convert(geosite, geoip, extra=None):
    """Rules JSON bytes and statistics from raw dat files. Deterministic for identical inputs."""
    sites, ips = load_geosite(geosite), load_geoip(geoip)
    coverage, sections, dropped = Coverage(), [], 0

    def add(target, entries=(), networks=()):
        nonlocal dropped
        good = [(t, v if t == 'regexp' else v.lower()) for t, v in entries if valid(t, v if t == 'regexp' else v.lower())]
        dropped += len(entries) - len(good)
        domains = section(good, coverage)
        addresses = [str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(n for n in networks if n.version == version)]
        if not domains and not addresses:
            return
        if sections and sections[-1]['target'] == target and not addresses and 'ips' not in sections[-1]:
            sections[-1]['domains'] += domains
            return
        item = {'target': target}
        if domains:
            item['domains'] = domains
        if addresses:
            item['ips'] = addresses
        sections.append(item)

    if extra:
        add('block', [('domain', v) for v in extra['blockedDomains']])
        add('proxy', [('domain', v) for v in extra['proxyDomains']])
        add('direct', [('domain', v) for v in extra['directDomains']] + [('full', v) for v in extra['directFullDomains']])
        add('direct', networks=[ipaddress.ip_network(v) for v in extra['directIPs']])
    for target, specs in SECTIONS:
        add(target, [(typ, value) for spec in specs for typ, value, _ in select(sites, spec)])
    networks = []
    for code in GEOIP_DIRECT:
        if code not in ips:
            raise KeyError(f'geoip has no category {code!r}')
        networks += ips[code]
    add('direct', networks=networks)

    domains = sum(len(s.get('domains', [])) for s in sections)
    addresses = sum(len(s.get('ips', [])) for s in sections)
    if domains > MAX_DOMAINS or addresses > MAX_IPS or len(sections) > 64:
        raise ValueError('Dataset exceeds client limits')
    data = (json.dumps({'schemaVersion': 2, 'sections': sections}, ensure_ascii=True, separators=(',', ':')) + '\n').encode()
    if len(data) > 33554432:
        raise ValueError('Dataset exceeds client limits')
    targets = {}
    for s in sections:
        targets[s['target']] = targets.get(s['target'], 0) + len(s.get('domains', []))
    return data, dict(sections=len(sections), domains=domains, ips=addresses, dropped=dropped, perTarget=targets, outputSha256=hashlib.sha256(data).hexdigest())


def fetch(url, expected=None):
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if expected is None:
        with urllib.request.urlopen(url + '.sha256sum', timeout=60) as response:
            expected = response.read().decode().split()[0]
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f'{url}: checksum mismatch')
    return data


def pinned(args):
    manifest = json.loads((RULES / 'manifest.json').read_text(encoding='utf-8'))
    data = {}
    for name in ('geosite', 'geoip'):
        source = manifest['sources'][name]
        local = getattr(args, name)
        data[name] = Path(local).read_bytes() if local else fetch(source['url'], source['sha256'])
        if hashlib.sha256(data[name]).hexdigest() != source['sha256']:
            raise ValueError(f'{name}: not the pinned source')
    return manifest, data


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('build', 'check'):
        command = sub.add_parser(name)
        command.add_argument('--geosite')
        command.add_argument('--geoip')
    latest = sub.add_parser('latest')
    latest.add_argument('out')
    latest.add_argument('extra', nargs='?')
    args = parser.parse_args()
    if args.command == 'latest':
        output, stats = convert(fetch(LATEST['geosite']), fetch(LATEST['geoip']), load_extra(args.extra) if args.extra else None)
        Path(args.out).write_bytes(output)
        print(json.dumps(dict(stats, bytes=len(output))))
        return
    manifest, sources = pinned(args)
    output, stats = convert(sources['geosite'], sources['geoip'])
    if args.command == 'check':
        if stats['outputSha256'] != manifest['baseline.json'] or (RULES / 'baseline.json').read_bytes() != output:
            raise ValueError('The committed baseline differs from the pinned sources')
    else:
        (RULES / 'baseline.json').write_bytes(output)
        manifest['baseline.json'] = stats['outputSha256']
        (RULES / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(stats, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        sys.exit(f'Rule conversion failed, no partial dataset written: {error}')
