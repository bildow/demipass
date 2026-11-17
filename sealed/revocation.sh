#!/bin/sh
# Fixture-only, one OS-locked journal writer. Kernel releases the lock on exit/crash.
set -eu
umask 077
[ "$#" -eq 2 ] || exit 2
instance=$1
[ -d "$instance" ] && [ ! -L "$instance" ] || exit 2
[ "$(stat -c %u -- "$instance")" = "$(id -u)" ] || exit 2
[ "$(stat -c %a -- "$instance")" = 700 ] || exit 2
[ ! -L "$instance/lease.lock" ] || exit 2
if [ -e "$instance/lease.lock" ]; then
  [ -f "$instance/lease.lock" ] || exit 2
  [ "$(stat -c %u -- "$instance/lease.lock")" = "$(id -u)" ] || exit 2
  [ "$(stat -c %a -- "$instance/lease.lock")" = 600 ] || exit 2
fi
exec 9>>"$instance/lease.lock"
/usr/bin/flock --exclusive --nonblock 9 || exit 3
exec node "$(dirname "$0")/revocation-cli.js" "$instance" "$2"
