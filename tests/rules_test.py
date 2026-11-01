"""Remote rule conversion: the pinned baseline stays reproducible and operator additions are validated."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('import_rules', ROOT / 'tools/import-rules.py')
rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules)
SOURCES = {name: (ROOT / 'resources/rules/source' / name).read_bytes() for name in ('direct.txt', 'cncidr.txt')}


def extra(**values):
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as stream:
        json.dump(values, stream)
    try:
        return rules.load_extra(stream.name)
    finally:
        Path(stream.name).unlink()


class RuleConversion(unittest.TestCase):
    def test_without_additions_matches_pinned_baseline(self):
        data, _ = rules.convert(SOURCES)
        manifest = json.loads((ROOT / 'resources/rules/manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(hashlib.sha256(data).hexdigest(), manifest['files']['baseline.json'])

    def test_committed_additions_file_is_valid(self):
        rules.load_extra(ROOT / 'config/rules-extra.json')

    def test_additions_are_merged_and_deduplicated(self):
        additions = extra(proxyDomains=['Example.ORG', 'example.org'], blockedDomains=['ads.example'], directDomains=['baidu.com', 'intranet.example'],
                          directFullDomains=['exact.example'], directIPs=['192.0.2.0/24', '2001:db8::/32'])
        output = json.loads(rules.convert(SOURCES, additions)[0])
        self.assertEqual(output['proxyDomains'], ['example.org'])
        self.assertEqual(output['blockedDomains'], ['ads.example'])
        self.assertEqual(output['directDomains'].count('baidu.com'), 1)
        self.assertIn('intranet.example', output['directDomains'])
        self.assertIn('exact.example', output['directFullDomains'])
        self.assertEqual(output['directIPs'][-2:], ['192.0.2.0/24', '2001:db8::/32'])

    def test_invalid_additions_are_rejected(self):
        for values in [dict(proxyDomains=['bad..domain']), dict(proxyDomains=['+.example.org']), dict(blockedDomains=['-bad.example']),
                       dict(directIPs=['1.1.1.1/01']), dict(directIPs=['10.0.0.0/33']), dict(directIPs=['01.2.3.4']), dict(directIPs=['fe80::1%eth0']),
                       dict(proxyDomain=['typo.example']), dict(proxyDomains='example.org'), dict(comment=1)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                extra(**values)


if __name__ == '__main__':
    unittest.main()
