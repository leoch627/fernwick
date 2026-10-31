"""Packaging contracts: no installation or network changes are performed."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('packager', ROOT / 'tools/package.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class PackagingContracts(unittest.TestCase):
    def setUp(self):
        self.config = packager.read_json(ROOT / 'config/development.json')
        self.manifest = packager.read_json(ROOT / 'resources/native-manifest.json')

    def test_executable_names_match_native_helper_contract(self):
        self.assertEqual(packager.executable_name(self.config, 'linux-x64'), self.config['productId'])
        self.assertEqual(packager.executable_name(self.config, 'win32-x64'), self.config['name'] + ' Dev.exe')
        self.assertEqual(packager.executable_name(self.config, 'darwin-arm64'), self.config['name'] + ' Dev')

    def test_native_resources_require_both_helper_and_core(self):
        missing = {**self.manifest, 'components': [c for c in self.manifest['components'] if c['type'] != 'helper']}
        with self.assertRaisesRegex(ValueError, 'Missing .* helper'):
            packager.expected_resources('linux-x64', missing)

    def test_resource_paths_cannot_escape_staging_directory(self):
        manifest = {**self.manifest, 'components': [{'type': 'core', 'target': 'linux-x64', 'file': '../escape', 'sha256': 'a' * 64}]}
        with self.assertRaisesRegex(ValueError, 'Unexpected native manifest path'):
            packager.expected_resources('linux-x64', manifest)

    def test_resource_hashes_detect_changes_after_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'core-lock.json').write_bytes(b'original')
            expected = {'core-lock.json': packager.sha(root / 'core-lock.json')}
            (root / 'core-lock.json').write_bytes(b'modified')
            with patch.object(packager, 'expected_resources', return_value=expected):
                with self.assertRaisesRegex(ValueError, 'modified'):
                    packager.verify_resources(root, 'linux-x64', self.manifest)

    def test_linux_upgrade_preserves_helper_recovery_and_no_chromium(self):
        scripts = packager.linux_scripts(self.config)
        self.assertIn('helper" install --app "$APP"', scripts['postinst'])
        self.assertIn('upgrade', scripts['prerm'])
        self.assertIn('systemctl stop ' + self.config['productId'], scripts['prerm'])
        self.assertIn('helper uninstall', scripts['prerm'])
        self.assertIn('update-alternatives --remove', scripts['postrm'])
        self.assertNotIn('chrome-sandbox', ''.join(scripts.values()))
        self.assertIn('libwebkit2gtk-4.1-0', packager.LINUX_DEPENDS)
        self.assertNotIn('libnss3', packager.LINUX_DEPENDS)

    def test_nsis_parameters_are_literals(self):
        self.assertEqual(packager.nsis_literal('$evil"\n'), '$$evil$\\"$\\n')
        script = (ROOT / 'packaging/windows/installer.nsi').read_text()
        self.assertIn('RequestExecutionLevel admin', script)
        self.assertIn('SetErrorLevel 1', script)
        self.assertIn('helper.exe" uninstall', script)
        self.assertNotIn('isUpdated', script)


if __name__ == '__main__':
    unittest.main()
