#!/bin/sh
set -eu
# @SERVICE_ID@ is replaced with the build's productId by tools/package.py.
# dpkg passes upgrade during replacement. Let the new helper preserve/replace the service.
if [ "${1:-}" = 'upgrade' ]; then
  if [ -x /usr/lib/@SERVICE_ID@/helper ]; then systemctl stop @SERVICE_ID@.service; fi
elif [ -x /usr/lib/@SERVICE_ID@/helper ]; then
  /usr/lib/@SERVICE_ID@/helper uninstall
fi
