#!/usr/bin/env python3
"""Build and package the Wails desktop executable without installing the app."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import zlib

ROOT = Path(__file__).resolve().parents[1]
MACOS_MINIMUM = '14.0'
TARGETS = {'linux-x64': ('linux', 'amd64', 'linux-unpacked', 'linux-amd64'),
           'win32-x64': ('windows', 'amd64', 'win-unpacked', 'windows-x64'),
           'darwin-arm64': ('darwin', 'arm64', 'mac-arm64', 'macos-arm64'),
           'darwin-x64': ('darwin', 'amd64', 'mac', 'macos-x64')}
LINUX_DEPENDS = ['libgtk-3-0t64', 'libwebkit2gtk-4.1-0', 'libsecret-1-0', 'iproute2', 'nftables', 'systemd-resolved', 'polkitd', 'pkexec', 'dpkg-repack']


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def sha(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(args, *, cwd=ROOT, env=None):
    print('+ ' + shlex.join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True)


def product_name(config):
    return config['name'] + (' Dev' if config['environment'] == 'test' else '')


def executable_name(config, target):
    return config['productId'] if target.startswith('linux-') else product_name(config) + ('.exe' if target.startswith('win32-') else '')


def check_helper_configuration(config, manifest, version):
    helper = read_json(ROOT / 'native/helper/build.json')
    origins = sorted(set([e['baseUrl'].rstrip('/') for e in config['apiEndpoints']] + config['trustedSubscriptionOrigins'] + config['trustedResourceOrigins'] +
                         [urlsplit(u)._replace(path='', query='', fragment='').geturl() for u in config['policyUrls'] + config['updateFeedUrls']]))
    expected = {'productId': config['productId'], 'displayName': product_name(config), 'helperLabel': config['appId'] + '.helper',
                'environment': config['environment'], 'channel': config['channel'], 'version': version, 'controlOrigins': origins,
                'healthTargets': config['healthTargets'], 'updateKeys': config['updateKeys'], 'trustedUpdateOrigins': config['trustedUpdateOrigins'], 'buildId': manifest['buildId'],
                'appExecutableNames': {target: executable_name(config, target) for target in TARGETS}}
    wrong = [key for key, value in expected.items() if helper.get(key) != value]
    if wrong:
        raise ValueError('Helper configuration differs from packaged configuration (' + ', '.join(wrong) + '). Run native:build with the same STARRAIL_BUILD_CONFIG.')


def expected_resources(target, manifest):
    lock = read_json(ROOT / 'resources/core-lock.json')
    asset = next(a for a in lock['assets'] if a['target'] == target)
    entries = {f'native/{target}/LICENSE': asset['licenseSha256']}
    for kind in ['core', 'helper']:
        component = next((c for c in manifest['components'] if c['target'] == target and c['type'] == kind), None)
        if component is None:
            raise ValueError(f'Missing {target} {kind}; run core:fetch and native:build first')
        expected_name = asset['executable'] if kind == 'core' else ('helper.exe' if target.startswith('win32-') else 'helper')
        if Path(component['file']).as_posix() != f'resources/native/{target}/{expected_name}':
            raise ValueError('Unexpected native manifest path')
        entries[f'native/{target}/{expected_name}'] = component['sha256']
    entries.update({f'native/{target}/{name}': value for name, value in asset.get('extras', {}).items()})
    entries['rules/baseline.json'] = read_json(ROOT / 'resources/rules/manifest.json')['baseline.json']
    return entries


def verify_resources(root, target, manifest):
    for name, expected in expected_resources(target, manifest).items():
        path = root / name
        if not path.is_file() or path.is_symlink() or sha(path) != expected:
            raise ValueError(f'Packaged resource missing or modified: {path}')
    for name in ['core-lock.json', 'native-manifest.json', 'THIRD_PARTY_NOTICES.md', 'rules/manifest.json']:
        if not (root / name).is_file():
            raise ValueError(f'Missing packaged resource: {name}')


def copy_resources(destination, target, manifest):
    destination.mkdir(parents=True, exist_ok=True)
    for name, expected in expected_resources(target, manifest).items():
        if sha(ROOT / 'resources' / name) != expected:
            raise ValueError(f'Native/rule input hash mismatch: {name}')
    shutil.copytree(ROOT / 'resources/native' / target, destination / 'native' / target)
    for directory in ['rules', 'licenses']:
        shutil.copytree(ROOT / 'resources' / directory, destination / directory)
    for name in ['core-lock.json', 'native-manifest.json']:
        shutil.copy2(ROOT / 'resources' / name, destination / name)
    shutil.copy2(ROOT / 'THIRD_PARTY_NOTICES.md', destination / 'THIRD_PARTY_NOTICES.md')
    verify_resources(destination, target, manifest)


def normalize_permissions(directory):
    directory.chmod(0o755)
    for path in directory.rglob('*'):
        if path.is_symlink():
            continue
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)


def windows_resources(config, version):
    work = ROOT / 'work/packaging/windows'
    work.mkdir(parents=True, exist_ok=True)
    numeric = version.split('-')[0].split('+')[0]
    components = numeric.split('.')
    if len(components) != 3 or any(not s.isdigit() or int(s) > 65535 for s in components):
        raise ValueError('Windows version must have three 16-bit numeric components')
    fixed = numeric + '.0'
    shutil.copy2(ROOT / 'resources/icon.png', work / 'icon.png')
    resource = {'RT_GROUP_ICON': {'APP': {'0000': 'icon.png'}},
                'RT_MANIFEST': {'#1': {'0409': {'minimum-os': 'win10', 'execution-level': '', 'dpi-awareness': 'per monitor v2', 'long-path-aware': True}}},
                'RT_VERSION': {'#1': {'0000': {'fixed': {'file_version': fixed, 'product_version': fixed}, 'info': {'0409': {
                    'FileDescription': product_name(config), 'ProductName': product_name(config), 'FileVersion': version,
                    'ProductVersion': version, 'OriginalFilename': executable_name(config, 'win32-x64'), 'InternalName': config['productId']}}}}}}
    definition = work / 'winres.json'
    definition.write_text(json.dumps(resource, ensure_ascii=False, indent=2), encoding='utf-8')
    run([os.environ.get('STARRAIL_GO', 'go'), 'run', 'github.com/tc-hib/go-winres@v0.3.3', 'make', '--in', definition, '--out', ROOT / 'desktop/rsrc', '--arch', 'amd64'])
    return ROOT / 'desktop/rsrc_windows_amd64.syso'


def build_binary(config, target, version):
    goos, goarch, _, _ = TARGETS[target]
    if goos in ('darwin', 'linux') and platform.system().lower() != goos:
        raise ValueError(f'{target} requires a native {goos} builder with CGO dependencies')
    output = ROOT / 'dist/desktop' / target / executable_name(config, target)
    output.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'GOOS': goos, 'GOARCH': goarch, 'CGO_ENABLED': '0' if goos == 'windows' else '1'}
    if goos == 'darwin':
        env['MACOSX_DEPLOYMENT_TARGET'] = MACOS_MINIMUM
    syso = windows_resources(config, version) if goos == 'windows' else None
    try:
        flags = '-s -w' + (' -H windowsgui' if goos == 'windows' else '')
        if goos == 'darwin':
            # Wails carries older per-package deployment flags. Make the final
            # Mach-O load command agree with the bundle's supported minimum.
            flags += ' -extldflags=-mmacosx-version-min=' + MACOS_MINIMUM
        tags = 'production,gtk3' if goos == 'linux' else 'production'
        run([os.environ.get('STARRAIL_GO', 'go'), 'build', '-tags', tags, '-trimpath', '-buildvcs=false', '-ldflags', flags, '-o', output, '.'], cwd=ROOT / 'desktop', env=env)
    finally:
        if syso is not None:
            syso.unlink(missing_ok=True)
    output.chmod(0o755)
    return output


def mac_icon(destination):
    iconset = ROOT / 'work/packaging/icon.iconset'
    if iconset.exists():
        shutil.rmtree(iconset)
    iconset.mkdir(parents=True)
    for size in [16, 32, 128, 256, 512]:
        for scale in [1, 2]:
            name = f'icon_{size}x{size}' + ('@2x' if scale == 2 else '') + '.png'
            run(['/usr/bin/sips', '-z', str(size * scale), str(size * scale), ROOT / 'resources/icon.png', '--out', iconset / name])
    run(['/usr/bin/iconutil', '-c', 'icns', iconset, '-o', destination])


def package_macos(config, version, target, binary, stage, manifest):
    product = product_name(config)
    app = stage / (product + '.app')
    macos, resources = app / 'Contents/MacOS', app / 'Contents/Resources'
    macos.mkdir(parents=True)
    shutil.copy2(binary, macos / binary.name)
    copy_resources(resources, target, manifest)
    mac_icon(resources / 'icon.icns')
    info = {'CFBundleIdentifier': config['appId'], 'CFBundleName': product, 'CFBundleDisplayName': product,
            'CFBundleExecutable': binary.name, 'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': version,
            'CFBundleVersion': version, 'CFBundleIconFile': 'icon.icns', 'LSMinimumSystemVersion': MACOS_MINIMUM,
            'LSApplicationCategoryType': 'public.app-category.utilities', 'NSHighResolutionCapable': True,
            'NSHumanReadableCopyright': config['name']}
    with (app / 'Contents/Info.plist').open('wb') as stream:
        plistlib.dump(info, stream)
    normalize_permissions(app)
    identity = os.environ.get('STARRAIL_MAC_SIGN_IDENTITY', '-')
    flags = ['--options', 'runtime', '--timestamp'] if identity != '-' else []
    run(['/usr/bin/codesign', '--force', '--sign', identity, *flags, app])
    run(['/usr/bin/codesign', '--verify', '--strict', app])
    verify_resources(resources, target, manifest)
    stem = config['productId'] + '-' + version + '-' + TARGETS[target][3]
    archive = ROOT / 'release' / (stem + '.zip')
    archive.unlink(missing_ok=True)
    run(['/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, archive])
    dmg = ROOT / 'release' / (stem + '.dmg')
    dmg.unlink(missing_ok=True)
    build_dmg(product, app, resources / 'icon.icns', target, dmg)
    for artifact in (archive, dmg):
        verify_macos_artifact(artifact, app, target, manifest)


def verify_macos_artifact(artifact, source_app, target, manifest):
    """Check what users extract or mount, after the archive/DMG tools have run."""
    with tempfile.TemporaryDirectory(prefix='starrail-package-') as directory:
        extracted = Path(directory) / 'contents'
        extracted.mkdir()
        mounted = False
        try:
            if artifact.suffix == '.dmg':
                run(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-noautoopen',
                     '-mountpoint', extracted, artifact])
                mounted = True
            elif artifact.suffix == '.zip':
                run(['/usr/bin/ditto', '-x', '-k', artifact, extracted])
            else:
                raise ValueError('Expected a macOS ZIP or DMG')
            app = extracted / source_app.name
            run(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
            expected_info = plistlib.loads((source_app / 'Contents/Info.plist').read_bytes())
            if plistlib.loads((app / 'Contents/Info.plist').read_bytes()) != expected_info:
                raise ValueError('Archived application metadata differs from the signed bundle')
            executable = Path('Contents/MacOS') / expected_info['CFBundleExecutable']
            if sha(app / executable) != sha(source_app / executable):
                raise ValueError('Archived application executable differs from the signed bundle')
            verify_resources(app / 'Contents/Resources', target, manifest)
        finally:
            if mounted:
                run(['/usr/bin/hdiutil', 'detach', extracted])


# The DMG window: packaging/macos/dmg-background.html draws the drop targets at these points.
DMG_WINDOW = (660, 420)
DMG_ICONS = {'app': (170, 190), 'Applications': (490, 190)}


def build_dmg(product, app, icns, target, dmg):
    """A designed DMG (background, icon layout, volume icon) via dmgbuild, which writes
    Finder's view settings directly, so it needs no Finder scripting on the build host."""
    try:
        import dmgbuild
    except ImportError:
        dmgbuild = None
    if dmgbuild is None:
        print('dmgbuild is not installed (pip install dmgbuild==1.6.7): building a plain DMG.', flush=True)
        dmg_source = ROOT / 'work/packaging' / ('dmg-' + target)
        if dmg_source.exists():
            shutil.rmtree(dmg_source)
        dmg_source.mkdir(parents=True)
        (dmg_source / 'Applications').symlink_to('/Applications')
        # hdiutil does not dereference application symlinks: stage a real copy.
        shutil.copytree(app, dmg_source / app.name, symlinks=True)
        run(['/usr/bin/hdiutil', 'create', '-volname', product, '-srcfolder', dmg_source, '-ov', '-format', 'UDZO', dmg])
        return
    background = ROOT / 'packaging/macos/dmg-background.png'
    settings = {
        'format': 'UDZO', 'files': [str(app)], 'symlinks': {'Applications': '/Applications'},
        'icon': str(icns), 'background': str(background),  # dmgbuild adds the @2x image for Retina
        'window_rect': ((200, 120), DMG_WINDOW), 'default_view': 'icon-view',
        'show_status_bar': False, 'show_tab_view': False, 'show_toolbar': False, 'show_pathbar': False, 'show_sidebar': False,
        'show_icon_preview': False, 'arrange_by': None, 'label_pos': 'bottom', 'icon_size': 112, 'text_size': 13,
        'icon_locations': {app.name: DMG_ICONS['app'], 'Applications': DMG_ICONS['Applications']},
        # Hiding .app writes com.apple.FinderInfo to the already signed bundle.
        # That makes the delivered app fail codesign --strict (even if staging passed).
    }
    print(f'+ dmgbuild {dmg.name}', flush=True)
    dmgbuild.build_dmg(str(dmg), product, settings=settings)


def read_png(path):
    """Decode an 8-bit, non-interlaced RGB or RGBA PNG into (width, height, RGBA rows)."""
    data = Path(path).read_bytes()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('not a PNG file')
    offset, chunks, header = 8, [], None
    while offset < len(data):
        length, kind = struct.unpack('>I4s', data[offset:offset + 8])
        body = data[offset + 8:offset + 8 + length]
        if kind == b'IHDR':
            header = struct.unpack('>IIBBBBB', body)
        elif kind == b'IDAT':
            chunks.append(body)
        offset += 12 + length
    width, height, depth, color, _, _, interlace = header
    if depth != 8 or color not in (2, 6) or interlace:
        raise ValueError('icon must be an 8-bit, non-interlaced RGB or RGBA PNG')
    channels = 4 if color == 6 else 3
    raw, stride = zlib.decompress(b''.join(chunks)), width * channels
    rows, previous = [], bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for i in range(stride):
            left = line[i - channels] if i >= channels else 0
            up, corner = previous[i], previous[i - channels] if i >= channels else 0
            if kind == 1:
                line[i] = (line[i] + left) & 255
            elif kind == 2:
                line[i] = (line[i] + up) & 255
            elif kind == 3:
                line[i] = (line[i] + ((left + up) >> 1)) & 255
            elif kind == 4:
                estimate = left + up - corner
                pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - corner)
                line[i] = (line[i] + (left if pa <= pb and pa <= pc else up if pb <= pc else corner)) & 255
        previous = line
        if channels == 3:
            line = bytearray(b''.join(bytes(line[i:i + 3]) + b'\xff' for i in range(0, stride, 3)))
        rows.append(line)
    return width, height, rows


def resample(width, height, rows, size):
    """Area-average an RGBA image to size x size, in premultiplied alpha."""
    def taps(source):
        scale, result = source / size, []
        for out in range(size):
            begin, end = out * scale, (out + 1) * scale
            weights = [(i, min(end, i + 1) - max(begin, i)) for i in range(int(begin), min(source, int(end) + 1)) if min(end, i + 1) > max(begin, i)]
            result.append([(i, w / scale) for i, w in weights])
        return result
    premultiplied = []
    for line in rows:
        values = []
        for x in range(width):
            r, g, b, a = line[4 * x:4 * x + 4]
            values.append((r * a, g * a, b * a, a))
        premultiplied.append(values)
    horizontal = [[tuple(sum(row[i][c] * w for i, w in tap) for c in range(4)) for tap in taps(width)] for row in premultiplied]
    result = []
    for tap in taps(height):
        line = bytearray()
        for x in range(size):
            r, g, b, a = (sum(horizontal[i][x][c] * w for i, w in tap) for c in range(4))
            line += bytes((round(r / a), round(g / a), round(b / a), round(a))) if a >= 0.5 else b'\0\0\0\0'
        result.append(line)
    return result


def png_bytes(size, rows):
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body) & 0xffffffff)
    raw = b''.join(b'\0' + bytes(line) for line in rows)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b'')


def ico_bytes(source, sizes=(16, 24, 32, 48, 64, 128, 256)):
    """A Windows icon of source at every size Explorer and the installer use: 32-bit
    bitmaps up to 128 px and a PNG image at 256 px, as Windows' own icons are stored."""
    width, height, rows = read_png(source)
    if width < max(sizes) or height < max(sizes):
        raise ValueError('icon must be at least 256 x 256 pixels')
    # Halve to 256 px first; each size is then averaged from that.
    base = resample(width, height, rows, 256) if width != 256 or height != 256 else rows
    images = []
    for size in sizes:
        pixels = base if size == 256 else resample(256, 256, base, size)
        if size == 256:
            images.append((size, png_bytes(size, pixels)))
            continue
        mask_stride = ((size + 31) // 32) * 4
        header = struct.pack('<IiiHHIIiiII', 40, size, size * 2, 1, 32, 0, size * size * 4 + mask_stride * size, 0, 0, 0, 0)
        # Bitmap rows run bottom-up in BGRA; the AND mask is unused with an alpha channel.
        bgra = b''.join(bytes(b for x in range(0, 4 * size, 4) for b in (line[x + 2], line[x + 1], line[x], line[x + 3])) for line in reversed(pixels))
        images.append((size, header + bgra + bytes(mask_stride * size)))
    directory = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, body in images:
        directory += struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(body), offset)
        offset += len(body)
    return directory + b''.join(body for _, body in images)


def composite(rows, x0, y0, canvas):
    """Draw RGBA rows over an RGB canvas (a list of bytearrays) at x0, y0."""
    for y, line in enumerate(rows):
        target = canvas[y0 + y]
        for x in range(len(line) // 4):
            r, g, b, a = line[4 * x:4 * x + 4]
            i = 3 * (x0 + x)
            for c, value in enumerate((r, g, b)):
                target[i + c] = (value * a + target[i + c] * (255 - a) + 127) // 255


def wizard_bmp(source, width=164, height=314):
    """The installer's welcome and finish side image: the app icon on its own colour, in
    place of NSIS's stock artwork. A 24-bit bitmap, as NSIS requires."""
    w, h, rows = read_png(source)
    icon = resample(w, h, rows, 112)
    middle = icon[len(icon) // 2]
    colour = bytes(middle[16:19])  # inside the icon's border, clear of the mark
    canvas = [bytearray(colour * width) for _ in range(height)]
    composite(icon, (width - 112) // 2, 78, canvas)
    stride = (width * 3 + 3) & ~3
    pixels = b''.join(bytes(b for x in range(width) for b in (line[3 * x + 2], line[3 * x + 1], line[3 * x])).ljust(stride, b'\0') for line in reversed(canvas))
    header = struct.pack('<IiiHHIIiiII', 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    return b'BM' + struct.pack('<IHHI', 14 + len(header) + len(pixels), 0, 0, 14 + len(header)) + header + pixels


def nsis_literal(value):
    return str(value).replace('$', '$$').replace('"', '$\\"').replace('\n', '$\\n').replace('\r', '$\\r')


def package_windows(config, version, target, binary, stage, manifest):
    shutil.copy2(binary, stage / binary.name)
    copy_resources(stage / 'resources', target, manifest)
    script = (ROOT / 'packaging/windows/installer.nsi').read_text(encoding='utf-8')
    output = ROOT / 'release' / f"{config['productId']}-{version}-windows-x64.exe"
    icon, wizard = ROOT / 'work/packaging/installer.ico', ROOT / 'work/packaging/installer-wizard.bmp'
    icon.parent.mkdir(parents=True, exist_ok=True)
    icon.write_bytes(ico_bytes(ROOT / 'resources/icon.png'))
    wizard.write_bytes(wizard_bmp(ROOT / 'resources/icon.png'))
    replacements = {'PRODUCT_NAME': product_name(config), 'PRODUCT_ID': config['productId'], 'APP_ID': config['appId'],
                    'VERSION': version, 'NUMERIC_VERSION': version.split('-')[0].split('+')[0] + '.0',
                    'EXE_NAME': binary.name, 'STAGE': stage, 'OUTPUT': output, 'ICON': icon, 'WIZARD': wizard}
    for name, value in replacements.items():
        script = script.replace('@' + name + '@', nsis_literal(value))
    definition = ROOT / 'work/packaging/installer.nsi'
    definition.parent.mkdir(parents=True, exist_ok=True)
    # A byte order mark tells makensis the script (Chinese text, product name) is UTF-8.
    definition.write_text(script, encoding='utf-8-sig')
    makensis = shutil.which('makensis')
    if not makensis and os.name == 'nt':
        for base in [os.environ.get('ProgramFiles(x86)', ''), os.environ.get('ProgramFiles', '')]:
            candidate = Path(base) / 'NSIS/makensis.exe'
            if candidate.is_file():
                makensis = str(candidate)
                break
    if not makensis:
        raise ValueError('makensis is required (Windows: choco install nsis; Linux: apt install nsis; macOS: brew install nsis)')
    # makensis on Linux/macOS crashes on non-ASCII file names unless the locale is UTF-8.
    run([makensis, '-V2', definition], env=None if os.name == 'nt' else {**os.environ, 'LC_ALL': 'C.UTF-8'})
    verify_resources(stage / 'resources', target, manifest)


def linux_scripts(config):
    product, executable = product_name(config), config['productId']
    substitutions = {'@APP_PATH@': shlex.quote('/opt/' + product), '@SERVICE_ID@': executable}
    result = {}
    for template, filename in [('after-install.sh', 'postinst'), ('before-remove.sh', 'prerm')]:
        value = (ROOT / 'packaging/linux' / template).read_text(encoding='utf-8')
        for name, replacement in substitutions.items():
            value = value.replace(name, replacement)
        result[filename] = value
    result['postrm'] = '#!/bin/sh\nset -eu\nif [ "${1:-}" = remove ]; then\n  update-alternatives --remove ' + shlex.quote(executable) + ' ' + shlex.quote('/opt/' + product + '/' + executable) + '\nfi\n'
    return result


def package_linux(config, version, target, binary, stage, manifest):
    product, executable = product_name(config), config['productId']
    shutil.copy2(binary, stage / binary.name)
    copy_resources(stage / 'resources', target, manifest)
    normalize_permissions(stage)
    tree = ROOT / 'work/packaging/linux-deb'
    if tree.exists():
        shutil.rmtree(tree)
    app = tree / 'opt' / product
    app.parent.mkdir(parents=True)
    shutil.copytree(stage, app)
    control = tree / 'DEBIAN'
    control.mkdir()
    size = sum(p.stat().st_size for p in stage.rglob('*') if p.is_file())
    (control / 'control').write_text(f"Package: {executable}\nVersion: {version}\nSection: net\nPriority: optional\nArchitecture: amd64\nMaintainer: {config['name']}\nInstalled-Size: {(size + 1023) // 1024}\nDepends: {', '.join(LINUX_DEPENDS)}\nDescription: {config['name']} desktop client\n", encoding='utf-8')
    for name, script in linux_scripts(config).items():
        path = control / name
        path.write_text(script, encoding='utf-8')
        path.chmod(0o755)
    applications = tree / 'usr/share/applications'
    applications.mkdir(parents=True)
    exec_path = ('/opt/' + product + '/' + executable).replace('%', '%%')
    desktop = f"[Desktop Entry]\nType=Application\nName={config['name']}\nExec=\"{exec_path}\"\nIcon={executable}\nTerminal=false\nCategories=Network;\nStartupWMClass={config['appId']}\n"
    (applications / (config['appId'] + '.desktop')).write_text(desktop, encoding='utf-8')
    icons = tree / 'usr/share/icons/hicolor/512x512/apps'
    icons.mkdir(parents=True)
    shutil.copy2(ROOT / 'resources/icon.png', icons / (executable + '.png'))
    normalize_permissions(tree)
    output = ROOT / 'release' / f'{executable}-{version}-linux-amd64.deb'
    run(['dpkg-deb', '--build', '--root-owner-group', tree, output])
    run([sys.executable, ROOT / 'tools/verify-package.py', output])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=list(TARGETS), action='append')
    parser.add_argument('--skip-ui', action='store_true', help='Use the current generated frontend (native manifest/config freshness is still checked)')
    parser.add_argument('--binary-only', action='store_true', help='Compile the application without generating an installer')
    args = parser.parse_args()
    os.chdir(ROOT)
    os.umask(0o022)
    if not args.skip_ui:
        run([os.environ.get('STARRAIL_NODE', 'node'), '--import', 'tsx', 'tools/build.ts'])
    config = read_json(ROOT / 'dist/build-config.json')
    manifest = read_json(ROOT / 'resources/native-manifest.json')
    version = read_json(ROOT / 'package.json')['version']
    for name in ['build-config.json', 'native-manifest.json']:
        actual = read_json(ROOT / 'desktop/assets' / name)
        expected = config if name == 'build-config.json' else manifest
        if actual != expected:
            raise ValueError('Embedded assets are stale; run npm run build after native:build')
    if (ROOT / 'desktop/assets/version.txt').read_text(encoding='utf-8').strip() != version:
        raise ValueError('Embedded application version is stale')
    check_helper_configuration(config, manifest, version)
    if config['environment'] == 'production':
        run([os.environ.get('STARRAIL_NODE', 'node'), '--import', 'tsx', 'tools/release-check.ts'])
    machine = 'arm64' if platform.machine().lower() in ['arm64', 'aarch64'] else 'x64'
    host = {'Darwin': 'darwin', 'Windows': 'win32', 'Linux': 'linux'}[platform.system()]
    targets = args.target or [host + '-' + machine]
    for target in targets:
        if target not in TARGETS:
            raise ValueError(f'Unsupported target {target}')
        binary = build_binary(config, target, version)
        if args.binary_only:
            continue
        stage = ROOT / 'release' / TARGETS[target][2]
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True)
        packager = package_macos if target.startswith('darwin-') else package_windows if target.startswith('win32-') else package_linux
        packager(config, version, target, binary, stage, manifest)
        print(f'Packaged {target} with verified native and routing resources.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, StopIteration) as error:
        raise SystemExit(f'Packaging failed: {error}')
