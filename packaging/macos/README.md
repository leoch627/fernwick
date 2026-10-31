On macOS, copy the signed app from the DMG to `/Applications`, then connect or choose Settings → Repair. The app invokes its packaged helper using the system administrator authorization dialog. The helper installs a root-owned launchd service and records the immutable application/core identities. No network is taken over merely by installing the service.

Independent recovery:

```sh
sudo '/Library/PrivilegedHelperTools/<appId>.helper/helper' repair
```

Uninstall the service before removing the application:

```sh
sudo '/Library/PrivilegedHelperTools/<appId>.helper/helper' uninstall
```

Production builds require Developer ID signing and notarization. The in-app ZIP updater checks the signed release index, file hash, code signature Team ID and Gatekeeper assessment before replacing the app. It keeps one application backup.

Build with `python3 tools/package.py --target darwin-arm64` (or `darwin-x64`). The packager assembles the app with an embedded frontend, signs the bundle without `--deep`, verifies native resource hashes, and emits DMG and ZIP files. `STARRAIL_MAC_SIGN_IDENTITY` selects an explicit identity; the default is ad-hoc (`-`). The packager does not notarize or publish.

打包器把 `MACOSX_DEPLOYMENT_TARGET`、最终链接器的 `-mmacosx-version-min` 和 `LSMinimumSystemVersion` 统一为 14.0。Wails 自带较早的 CGO 部署参数，单设环境变量不足以保证最终 Mach-O 的 `minos` 与应用声明一致。
