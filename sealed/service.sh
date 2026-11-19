#!/bin/sh
# Locked Linux runner; fixture or separately permitted TLS mode. flock's descriptor stays open in the Node process.
set -eu
# Apply before redirection: inherited 022 must still create a private 0600 lock.
umask 077
[ "$#" -eq 1 ] || { echo 'usage: service.sh PRIVATE_INSTANCE_DIRECTORY' >&2; exit 2; }
instance=$1
[ -d "$instance" ] && [ ! -L "$instance" ] || exit 2
[ "$(stat -c %u -- "$instance")" = "$(id -u)" ] || exit 2
[ "$(stat -c %a -- "$instance")" = 700 ] || exit 2
if [ -e "$instance/lease.lock" ] || [ -L "$instance/lease.lock" ]; then
  [ -f "$instance/lease.lock" ] && [ ! -L "$instance/lease.lock" ] || exit 2
  [ "$(stat -c %u -- "$instance/lease.lock")" = "$(id -u)" ] || exit 2
  [ "$(stat -c %a -- "$instance/lease.lock")" = 600 ] || exit 2
fi
exec 9>>"$instance/lease.lock"
/usr/bin/flock --exclusive --nonblock 9 || { echo 'instance already owned or lock unavailable' >&2; exit 3; }
exec node "$(dirname "$0")/service.js" "$instance"
