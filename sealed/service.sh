#!/bin/sh
# Fixture-only Linux runner. flock's descriptor stays open in the Node process.
set -eu
umask 077
[ "$#" -eq 1 ] || { echo 'usage: service.sh PRIVATE_INSTANCE_DIRECTORY' >&2; exit 2; }
instance=$1
[ -d "$instance" ] && [ ! -L "$instance" ] || exit 2
[ "$(stat -c %u -- "$instance")" = "$(id -u)" ] || exit 2
[ "$(stat -c %a -- "$instance")" = 700 ] || exit 2
[ ! -L "$instance/lease.lock" ] || exit 2
exec 9>>"$instance/lease.lock"
/usr/bin/flock --exclusive --nonblock 9 || { echo 'instance already owned or lock unavailable' >&2; exit 3; }
exec node "$(dirname "$0")/service.js" "$instance"
