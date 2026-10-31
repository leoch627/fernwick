#!/usr/bin/env python3
"""Package source and already-built artifacts. Does not run tests, install, or publish."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

root = Path(__file__).resolve().parent.parent
destination = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / 'work' / 'delivery'
destination.mkdir(parents=True, exist_ok=True)
version = json.loads((root / 'package.json').read_text())['version']
source = destination / f'StarRail-Network-{version}-source.zip'
excluded = {'.git', 'node_modules', 'dist', 'release', 'work', 'coverage', '__pycache__'}
files = sorted(path for path in root.rglob('*') if path.is_file() and not path.is_symlink() and not excluded.intersection(path.relative_to(root).parts) and not path.relative_to(root).is_relative_to('resources/native'))
with zipfile.ZipFile(source, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in files:
        if path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx', '.log'} or path.name.startswith('.env') and path.name != '.env.example':
            raise ValueError('Refusing to include key/log-shaped source file')
        archive.write(path, f'StarRail-Network-{version}/' + str(path.relative_to(root)))
artifacts = [source]
native = destination / f'StarRail-Network-{version}-native-components.zip'
with zipfile.ZipFile(native, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for path in sorted((root / 'resources/native').rglob('*')):
        if path.is_file(): archive.write(path, str(path.relative_to(root)))
    for name in ('resources/core-lock.json', 'resources/native-manifest.json', 'THIRD_PARTY_NOTICES.md'):
        archive.write(root / name, name)
    for path in sorted((root / 'resources/licenses').glob('*')):
        if path.is_file(): archive.write(path, str(path.relative_to(root)))
artifacts.append(native)
packages = [
    (root / 'release/linux' / f'StarRail Network Dev-{version}-linux-amd64.deb', f'starrail-network-dev_{version}_amd64.deb'),
    (root / 'release/windows' / f'StarRail Network Dev-{version}-win-x64.exe', f'StarRail-Network-Dev-{version}-Windows-x64.exe'),
]
for path, name in packages:
    # Incomplete NSIS uninstaller-generation stubs are small and are not deliverable installers.
    if path.exists() and path.stat().st_size > 20 * 1024 * 1024:
        target = destination / name
        shutil.copyfile(path, target)
        artifacts.append(target)
report = destination / '交付说明.md'
listing = '\n'.join('- ' + path.name for path in artifacts)
report.write_text(f'''# StarRail Network {version} 功能开发版

本轮按“先做功能，不跑测试”完成实现、编译与打包。没有运行单元测试、UI/核心冒烟、安装、真实 TUN 或升级测试。源码中的历史测试记录只属于上一版。

## 交付文件

{listing}

source.zip 是完整源码、配置、构建工具、需求和文档；不含依赖缓存。native-components.zip 包含四目标 Xray/helper、Windows Wintun 和许可证，可解压到源码根目录供离线构建使用。DEB 与 Windows EXE 是未正式签名的开发安装包；macOS DMG/ZIP 构建入口及四目标手动 CI 已提供，DMG 需在 macOS 构建机生成。

## 已接入功能

登录、套餐/流量/到期、双 API、订阅同步、缓存授权、节点选择、规则/全局、系统服务安装与修复、实际 Xray TUN、DNS/UDP/IPv6 检查、心跳与恢复、物理接口控制通道、签名策略/规则、断点下载、更新安装与备份回退、通知与诊断。

品牌 StarRail Network；主 https://api.starrail.work，备 https://host.leiterup.de；适配 wyx2685/v2board 的固定提交 cfabf395644b68c318751439e8510093cd3aaeb2。

未指定 TLS/REALITY 指纹时默认 hellochrome_120，以 X25519 作为初始密钥交换组；订阅显式有效指纹保留。不会把无效的 x25519 字符串写入 fingerprint。

## 使用

Linux Ubuntu 24.04 GNOME 安装 DEB；Windows 11 x64 运行 EXE 安装器。客户端使用普通用户打开，必要时由系统授权安装/修复服务。macOS app 放入 /Applications。登录后同步节点，选择规则/全局并连接；只有真实数据路径检查通过才显示已连接。

源码构建需要 Node.js 24、Python 3、Go 1.27.3。npm ci 后运行 npm run native:build、npm run build 与对应平台打包命令；已提供的 native-components 可免去核心下载。详细操作与离线修复见 docs/native-service.md。

运营策略/规则/更新发布源、公钥、正式平台签名与公证身份仍需实际运营配置。当前没有编造发布源或私钥；正式发布门禁保留。真实账号与平台行为由用户自行测试。

SHA256SUMS.txt 记录本次交付文件的哈希；编译成功不代表运行验收通过。
''', encoding='utf-8')
artifacts.append(report)
with (destination / 'SHA256SUMS.txt').open('w') as checksum:
    for path in artifacts:
        with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        checksum.write(f'{digest}  {path.name}\n')
print(json.dumps({'directory': str(destination), 'sourceFiles': len(files), 'artifacts': [{'name': path.name, 'bytes': path.stat().st_size} for path in artifacts]}, ensure_ascii=False))
