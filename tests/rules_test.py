"""Rule conversion: section order, deduplication, operator additions and limits, on synthetic v2fly data."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('import_rules', ROOT / 'tools/import-rules.py')
rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules)


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def field(number, payload):
    if isinstance(payload, int):
        return varint(number << 3) + varint(payload)
    if isinstance(payload, str):
        payload = payload.encode()
    return varint(number << 3 | 2) + varint(len(payload)) + payload


TYPES = {'keyword': 0, 'regexp': 1, 'domain': 2, 'full': 3}


def geosite(categories):
    """{name: [(type, value, [attrs])]} encoded as a GeoSiteList."""
    out = b''
    for name, domains in categories.items():
        entry = field(1, name.upper())
        for typ, value, attrs in domains:
            domain = field(1, TYPES[typ]) + field(2, value) + b''.join(field(3, field(1, a)) for a in attrs)
            entry += field(2, domain)
        out += field(1, entry)
    return out


def geoip(categories):
    out = b''
    for name, networks in categories.items():
        entry = field(1, name.upper())
        for address, prefix in networks:
            entry += field(2, field(1, bytes(address)) + field(2, prefix))
        out += field(1, entry)
    return out


def sites(**overrides):
    base = {name: [] for specs in rules.SECTIONS for spec in specs[1] for name in [spec.split('@')[0]]}
    base.update(overrides)
    return geosite(base)


IPS = geoip({'private': [([10, 0, 0, 0], 8)], 'cn': [([1, 0, 1, 0], 24), ([1, 0, 2, 0], 23), ([1, 0, 1, 0], 25)]})


def extra(**values):
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as stream:
        json.dump(values, stream)
    try:
        return rules.load_extra(stream.name)
    finally:
        Path(stream.name).unlink()


def convert(site_data, extra_lists=None):
    data, stats = rules.convert(site_data, IPS, extra_lists)
    return json.loads(data), stats


def targets(output):
    found = {}
    for section in output['sections']:
        for value in section.get('domains', []):
            found.setdefault(value, section['target'])
    return found


class RuleConversion(unittest.TestCase):
    def test_sections_follow_template_order(self):
        output, _ = convert(sites(**{
            'category-ads-all': [('domain', 'ads.example', [])],
            'category-ai-!cn': [('domain', 'openai.com', [])],
            'google': [('domain', 'google.com', []), ('full', 'dl.google.com', ['cn'])],
            'geolocation-!cn': [('domain', 'google.com', []), ('domain', 'example.org', []), ('full', 'dl.google.com', ['cn'])],
            'geolocation-cn': [('domain', 'baidu.com', []), ('keyword', 'taobao', [])],
            'apple': [('domain', 'apple.com', [])],
            'tld-cn': [('domain', 'cn', [])],
        }))
        found = targets(output)
        self.assertEqual(found['domain:ads.example'], 'block')
        self.assertEqual(found['domain:openai.com'], 'ai')
        self.assertEqual(found['full:dl.google.com'], 'direct')  # geolocation-!cn@cn precedes google
        self.assertEqual(found['domain:google.com'], 'proxy')
        self.assertEqual(found['domain:apple.com'], 'direct')
        self.assertEqual(found['keyword:taobao'], 'direct')
        self.assertEqual(found['domain:example.org'], 'proxy')
        self.assertEqual(output['sections'][-1], {'target': 'direct', 'ips': ['1.0.1.0/24', '1.0.2.0/23', '10.0.0.0/8']})

    def test_covered_domains_are_dropped(self):
        output, _ = convert(sites(**{
            'google': [('domain', 'google.com', [])],
            'geolocation-!cn': [('domain', 'mail.google.com', []), ('full', 'www.google.com', []), ('domain', 'example.org', []), ('domain', 'a.example.org', [])],
        }))
        domains = [d for s in output['sections'] for d in s.get('domains', [])]
        self.assertEqual(sorted(domains), ['domain:example.org', 'domain:google.com'])

    def test_adjacent_sections_with_one_target_merge(self):
        output, stats = convert(sites(telegram=[('domain', 't.me', [])], github=[('domain', 'github.com', [])], steam=[]))
        self.assertEqual([s['target'] for s in output['sections']], ['proxy', 'direct'])
        self.assertEqual(output['sections'][0]['domains'], ['domain:t.me', 'domain:github.com'])
        self.assertEqual(stats['sections'], 2)

    def test_invalid_entries_are_dropped(self):
        output, stats = convert(sites(**{'geolocation-!cn': [('domain', 'bad_domain.example', []), ('regexp', '(?=lookahead)', []), ('regexp', r'^ok\.example$', []), ('keyword', 'Good', [])]}))
        domains = output['sections'][0]['domains']
        self.assertEqual(domains, ['keyword:good', r'regexp:^ok\.example$'])
        self.assertEqual(stats['dropped'], 2)

    def test_operator_additions_take_priority(self):
        additions = extra(proxyDomains=['Example.ORG', 'example.org'], blockedDomains=['ads.example'], directDomains=['intranet.example'],
                          directFullDomains=['exact.example'], directIPs=['192.0.2.0/24', '2001:db8::/32'])
        output, _ = convert(sites(**{'geolocation-cn': [('domain', 'example.org', [])], 'category-ads-all': [('domain', 'other-ads.example', [])]}), additions)
        self.assertEqual(output['sections'][0], {'target': 'block', 'domains': ['domain:ads.example']})
        self.assertEqual(output['sections'][1], {'target': 'proxy', 'domains': ['domain:example.org']})
        self.assertEqual(output['sections'][2], {'target': 'direct', 'domains': ['domain:intranet.example', 'full:exact.example']})
        self.assertEqual(output['sections'][3], {'target': 'direct', 'ips': ['192.0.2.0/24', '2001:db8::/32']})
        self.assertNotIn('domain:example.org', targets({'sections': output['sections'][2:]}))

    def test_committed_additions_file_is_valid(self):
        rules.load_extra(ROOT / 'config/rules-extra.json')

    def test_invalid_additions_are_rejected(self):
        for values in ({'proxyDomains': ['bad domain']}, {'directIPs': ['300.0.0.0/8']}, {'unknown': []}, {'proxyDomains': 'example.org'}):
            with self.assertRaises(ValueError, msg=values):
                extra(**values)

    def test_missing_category_is_an_error(self):
        with self.assertRaises(KeyError):
            rules.convert(geosite({'private': []}), IPS)

    def test_committed_baseline_matches_manifest(self):
        data = (ROOT / 'resources/rules/baseline.json').read_bytes()
        manifest = json.loads((ROOT / 'resources/rules/manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(rules.hashlib.sha256(data).hexdigest(), manifest['baseline.json'])
        baseline = json.loads(data)
        self.assertEqual(baseline['schemaVersion'], 2)
        self.assertEqual({s['target'] for s in baseline['sections']}, {'direct', 'proxy', 'ai', 'block'})


if __name__ == '__main__':
    unittest.main()
