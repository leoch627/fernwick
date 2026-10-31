#!/bin/sh
set -eu
APP=@APP_PATH@
EXE='@SERVICE_ID@'
update-alternatives --install "/usr/bin/$EXE" "$EXE" "$APP/$EXE" 100
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database /usr/share/applications; fi
"$APP/resources/native/linux-x64/helper" install --app "$APP"
