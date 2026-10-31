#!/bin/sh
set -eu
APP='/opt/${sanitizedProductName}'
EXE='${executable}'
update-alternatives --install "/usr/bin/$EXE" "$EXE" "$APP/$EXE" 100
if [ -f "$APP/resources/apparmor-profile" ] && command -v apparmor_parser >/dev/null 2>&1; then
  cp "$APP/resources/apparmor-profile" "/etc/apparmor.d/$EXE"
  apparmor_parser --replace --write-cache --skip-read-cache "/etc/apparmor.d/$EXE"
fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database /usr/share/applications; fi
if [ -f "$APP/resources/native/linux-x64/helper" ]; then
  chmod 4755 "$APP/chrome-sandbox"
  "$APP/resources/native/linux-x64/helper" install --app "$APP"
fi
