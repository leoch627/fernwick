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

    def test_installer_uses_the_app_icon_and_makes_shortcuts(self):
        script = (ROOT / 'packaging/windows/installer.nsi').read_text()
        for line in ['!define MUI_ICON "@ICON@"', '!define MUI_UNICON "@ICON@"', '!define MUI_WELCOMEFINISHPAGE_BITMAP "@WIZARD@"']:
            self.assertIn(line, script)
        self.assertIn('CreateShortcut "$DESKTOP\\@PRODUCT_NAME@.lnk"', script)
        # Recorded only once the file exists, under a value the broken updates never wrote.
        self.assertIn('${If} ${FileExists} "$DESKTOP\\@PRODUCT_NAME@.lnk"\n    WriteRegDWORD HKLM "${UNINSTALL_KEY}" "DesktopShortcutMade" 1', script)
        self.assertNotIn('"DesktopShortcut" 1', script)

    def test_icon_file_holds_every_size(self):
        import struct
        data = packager.ico_bytes(ROOT / 'resources/icon.png')
        reserved, kind, count = struct.unpack('<HHH', data[:6])
        self.assertEqual((reserved, kind, count), (0, 1, 7))
        sizes = []
        for i in range(count):
            width, height, _, _, planes, bits, length, offset = struct.unpack('<BBBBHHII', data[6 + 16 * i:22 + 16 * i])
            size = width or 256
            sizes.append(size)
            self.assertEqual((width, height, planes, bits), (size % 256, size % 256, 1, 32))
            body = data[offset:offset + length]
            self.assertEqual(len(body), length)
            if size == 256:
                self.assertTrue(body.startswith(b'\x89PNG'))
            else:
                self.assertEqual(struct.unpack('<Iii', body[:12]), (40, size, size * 2))
                # Corners are transparent, the centre is the mark.
                stride = size * 4
                self.assertEqual(body[40 + 3], 0)
                centre = 40 + (size // 2) * stride + (size // 2) * 4
                self.assertEqual(body[centre + 3], 255)
        self.assertEqual(sizes, [16, 24, 32, 48, 64, 128, 256])
        bitmap = packager.wizard_bmp(ROOT / 'resources/icon.png')
        self.assertEqual(bitmap[:2], b'BM')
        self.assertEqual(struct.unpack('<iiHH', bitmap[18:30]), (164, 314, 1, 24))


if __name__ == '__main__':
    unittest.main()
