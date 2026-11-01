On macOS, copy the signed app from the DMG to `/Applications`, then connect or choose Settings → Repair. The app invokes its packaged helper using the system administrator authorization dialog. The helper installs a root-owned launchd service and records the immutable application/core identities. No network is taken over merely by installing the service.

Independent recovery:

```sh
sudo '/Library/PrivilegedHelperTools/<appId>.helper/helper' repair
```

Uninstall the service before removing the application:

```sh
sudo '/Library/PrivilegedHelperTools/<appId>.helper/helper' uninstall
```

The in-app ZIP updater checks the signed release index and the file hash, then `codesign --verify --deep --strict` on the extracted app. For a Developer ID build (the index names a Team ID) it also checks the Team ID and the Gatekeeper assessment; an ad-hoc build is published as `unsigned` and trusted through the signed index alone. With the network service installed, the service swaps the root-owned bundle and keeps one application backup; without it, the app replaces its own bundle (or asks for an administrator once when the bundle is not the user's). The app is then reopened with `--updated`.

Because the network service makes the bundle root-owned (its peer check requires that), Finder cannot drag-replace an installed copy ("some items had to be skipped… Locked"). Move the old app to the Trash first, or update from inside the app.

The DMG window (background, icon positions, volume icon) is built with `dmgbuild` (`pip install dmgbuild==1.6.7`); without it the packager falls back to a plain `hdiutil` image. The background is rendered from `dmg-background.html` by `node tools/render-dmg-background.mjs`.

Build with `python3 tools/package.py --target darwin-arm64` (or `darwin-x64`). The packager assembles the app with an embedded frontend, signs the bundle without `--deep`, verifies native resource hashes, and emits DMG and ZIP files. `STARRAIL_MAC_SIGN_IDENTITY` selects an explicit identity; the default is ad-hoc (`-`). The packager does not notarize or publish.

打包器把 `MACOSX_DEPLOYMENT_TARGET`、最终链接器的 `-mmacosx-version-min` 和 `LSMinimumSystemVersion` 统一为 14.0。Wails 自带较早的 CGO 部署参数，单设环境变量不足以保证最终 Mach-O 的 `minos` 与应用声明一致。
