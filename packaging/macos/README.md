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
