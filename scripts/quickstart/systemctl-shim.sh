#!/bin/sh
# A stand-in for /usr/bin/systemctl inside the CI container of the quickstart
# job, which has no systemd. It understands exactly the calls the quickstart
# makes: daemon-reload, enable --now UNIT, restart UNIT, stop UNIT, is-active UNIT. A unit
# is its /etc/systemd/system/UNIT.service ExecStart= line, run in the
# background with a pid file, then its ExecStartPost= line run to completion
# (as systemd does before `restart` returns). Anything else fails loudly.
set -eu
state=/run/qs-systemctl
mkdir -p "$state"
unit_file() { echo "/etc/systemd/system/$1.service"; }
stop() {
	if [ -f "$state/$1.pid" ]; then
		kill "$(cat "$state/$1.pid")" 2>/dev/null || true
		rm -f "$state/$1.pid"
	fi
}
start() {
	f=$(unit_file "$1")
	[ -f "$f" ] || { echo "Unit $1.service not found." >&2; exit 5; }
	cmd=$(sed -n 's/^ExecStart=//p' "$f" | head -n 1)
	[ -n "$cmd" ] || exit 1
	stop "$1"
	# shellcheck disable=SC2086
	nohup $cmd >"$state/$1.log" 2>&1 &
	echo $! >"$state/$1.pid"
	post=$(sed -n 's/^ExecStartPost=//p' "$f" | head -n 1)
	if [ -n "$post" ]; then sh -c "$post" || { stop "$1"; exit 1; }; fi
}
active() { [ -f "$state/$1.pid" ] && kill -0 "$(cat "$state/$1.pid")" 2>/dev/null; }
case "${1:-}" in
daemon-reload) exit 0 ;;
enable) [ "${2:-}" = --now ] && start "${3:?}" ;;
stop) stop "${2:?}" ;;
restart) start "${2:?}" ;;
is-active) active "${2:?}" ;;
*) echo "systemctl shim: unsupported: $*" >&2; exit 2 ;;
esac
