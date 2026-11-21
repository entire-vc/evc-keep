#!/bin/sh
# testbed-seen ID PATH: runs as root before every start of a consumer
# (ExecStartPre=+ in its unit). It copies the carrier, as the consumer is about
# to read it, into a root-only directory, so that the stand's harvest makes
# every value a consumer ever started on a leak-scan needle: also a value a
# rollback later took off the carrier. Stand-only; it never prints a carrier.
set -eu
d=/var/lib/testbed-seen
install -d -m 0700 -o root -g root "$d"
[ -e "$2" ] || exit 0
install -m 0600 -o root -g root "$2" "$d/$1.$(date +%s%N)"
