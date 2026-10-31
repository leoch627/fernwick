# 原生服务、构建和恢复

源码在 native/helper，无 CGO；使用 Go 1.27.3，依赖锁在 go.mod/go.sum。本轮不运行测试。

```sh
npm ci
python3 tools/fetch-core.py linux-x64
python3 tools/build-native.py --target linux-x64
npm run build
npm run package:test
```

其他目标为 win32-x64、darwin-x64、darwin-arm64。STARRAIL_GO 可指定 Go 路径；不传 --target 则编译四目标。编译不执行服务、不申请系统权限。Windows 资源包含官方归档中的 Wintun DLL/许可证。其他打包命令为 npm run package:windows 和 npm run package:macos。

GitHub Actions 的 package-development.yml 提供手动启动的四目标打包，包含 macOS DMG，不自动发布或运行平台测试。

## 安装

- Linux DEB 安装 /usr/lib/starrail-network/helper 并启用 starrail-network.service，依赖 iproute2、nftables、systemd-resolved、pkexec、dpkg-repack。连接前检查 /etc/resolv.conf 使用 resolved stub，不默默替换其他 DNS 配置。
- Windows NSIS 安装到系统目录，注册 StarRailNetwork LocalSystem 服务。每位用户的凭据仍保存在各自的数据目录。
- macOS 将 app 放进 /Applications，首次连接或“修复”通过系统授权安装 launchd 服务；代码文件由 root 持有。

实际连接才接管网络，GUI 不需要长期以管理员/root 运行。应用 hash、ASAR hash、核心 hash 和构建 ID 固定在安装记录中，修复重建匹配记录。

## 离线修复与卸载

Linux：

```sh
sudo /usr/lib/starrail-network/helper repair
sudo /usr/lib/starrail-network/helper uninstall
```

macOS：

```sh
sudo '/Library/PrivilegedHelperTools/work.starrail.network/helper' repair
sudo '/Library/PrivilegedHelperTools/work.starrail.network/helper' uninstall
```

Windows 管理员 PowerShell：

```powershell
& "$env:ProgramFiles\StarRail Network Service\helper.exe" repair
& "$env:ProgramFiles\StarRail Network Service\helper.exe" uninstall
```

repair 停止服务、按日志恢复所属资源并重启；卸载先恢复网络。Windows 当前执行的 helper 登记为重启后删除，不删除用户凭据目录或其他 VPN 资源。

连接事务使用单调时钟截止，失败时清理最多占用剩余的 3 秒，且为撤销临时防火墙保护保留独立时间。清理失败保留恢复日志并显示 RecoveryRequired；服务按 1、2、4 秒递增至最多 30 秒的间隔重试清理，不重新启动代理或建立阻断。常规断开及启动遗留清理使用 5 秒预算。以上时限为实现约束，实机验收留给用户执行。

## 原生签名顺序

签名改变 SHA-256，需在固定运行时哈希前完成：

1. fetch-core.py 获取原始锁定核心。
2. 在目标系统设置 STARRAIL_NATIVE_SIGN_IDENTITY，运行 python3 tools/sign-native.py core TARGET。Windows 可指定 STARRAIL_SIGNTOOL；macOS 开发包可用 - 进行 ad-hoc 签名，生产禁止。
3. 运行 build-native.py，把签名后的核心哈希编入 helper。
4. 运行 python3 tools/sign-native.py helper TARGET，把签名后 helper 哈希写入清单。
5. 最后 npm run build 与平台打包，按 electron-builder 的证书环境配置签名、公证。打包器不再次签名 native/xray、helper、Wintun，避免破坏哈希。

更新源、公钥集中在构建配置；私钥不进入客户端。Linux 更新以签名索引认证完整 DEB，Windows/macOS 另验证平台签名身份。保留一版备份，更新中断后由下次服务启动触发独立恢复。
