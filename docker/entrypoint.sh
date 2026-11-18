#!/bin/sh
set -eu
if [ "$(id -u)" = 0 ]; then
  mkdir -p /state /trust /reports
  chown lab:lab /state /trust 2>/dev/null || true
  if [ "${1:-}" = "/usr/local/bin/svc1" ]; then
    exec runuser -u lab -- "$@"
  fi
fi
exec "$@"
