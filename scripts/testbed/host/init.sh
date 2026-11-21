#!/bin/sh
# First boot of a host: its directories, the consumers' unit state and the
# keep-runner unit. No credential exists yet, so no consumer is started here:
# the first delivery starts it (the runner restarts the consumer).
set -eu
h=$(hostname)
mkdir -p /etc/keep /var/lib/keep-runner
case "$h" in
host-a) dirs="a1 a2 a3"; cons="consumer-a1 consumer-a2 consumer-a3"; pol=policy-host-a.json ;;
host-b) dirs="b1 b2";    cons="consumer-b1 consumer-b2"; pol=policy-host-b.json ;;
*) echo "unknown host $h" >&2; exit 1 ;;
esac
for x in $dirs; do
  mkdir -p /srv/app/$x
  chown root:root /srv/app/$x; chmod 0755 /srv/app/$x
done
# The consumers' files exist and belong to the consumer's user before the
# first delivery; a1/b1/b2 are created by the runner itself.
if [ "$h" = host-a ]; then
  [ -e /srv/app/a2/mcp.json ] || { printf '{"mcpServers":{"gateway":{"command":"gateway","env":{}}}}\n' >/srv/app/a2/mcp.json; chown 2001:2001 /srv/app/a2/mcp.json; chmod 0600 /srv/app/a2/mcp.json; }
fi
if [ ! -e /etc/keep/host-policy.json ]; then
  install -m 0600 /opt/testbed-host/$pol /etc/keep/host-policy.json
fi
echo "$cons" >/etc/keep/consumers
