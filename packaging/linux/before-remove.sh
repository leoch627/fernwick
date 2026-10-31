#!/bin/sh
set -eu
# dpkg passes upgrade during replacement. Let the new helper preserve/replace the service.
if [ "${1:-}" = 'upgrade' ]; then
  if [ -x /usr/lib/starrail-network/helper ]; then systemctl stop starrail-network.service; fi
elif [ -x /usr/lib/starrail-network/helper ]; then
  /usr/lib/starrail-network/helper uninstall
fi
