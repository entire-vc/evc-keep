#!/bin/sh
# One job owns the build cache; each unchanged check borrows it sequentially.
set -eu
[ "$#" -eq 0 ] || { echo 'FAIL: unexpected arguments' >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
supervisor=
pending_stop=0
finish() {
    status=$?
    trap - EXIT
    if [ "$status" -eq 125 ]; then
        # Supervisor could not prove the process group exited: retain the
        # private cache in this ephemeral job rather than remove live input.
        gocache_owned_path=
    fi
    gocache_cleanup
    exit "$status"
}
stop() {
    status=$1
    trap '' HUP INT TERM
    if [ -n "$supervisor" ]; then
        kill -TERM "$supervisor" 2>/dev/null || true
        child_status=0
        wait "$supervisor" || child_status=$?
        [ "$child_status" -ne 125 ] || gocache_owned_path=
    fi
    exit "$status"
}
trap finish EXIT
trap 'pending_stop=129; [ -z "$supervisor" ] || stop 129' HUP
trap 'pending_stop=130; [ -z "$supervisor" ] || stop 130' INT
trap 'pending_stop=143; [ -z "$supervisor" ] || stop 143' TERM
python3 - "$root" <<'PY' &
import os
import signal
import subprocess
import sys
import time

active = None
stopping = False


def stop(signum, frame):
    global stopping
    stopping = True
    signal.alarm(10)
    if active is not None:
        try:
            os.killpg(active.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def force_stop(signum, frame):
    if active is not None:
        try:
            os.killpg(active.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


signal.signal(signal.SIGALRM, force_stop)
for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, stop)

def drain_group(pid):
    # A child can exit before a descendant finishes handling TERM.
    # Never clean a cache while that group is still observable.
    for attempt in range(2):
        end = time.monotonic() + 1
        while time.monotonic() < end:
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(.01)
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True
    return False


for script in (
    "check-builtin-mutations.sh",
    "check-intake-receiver-mutations.sh",
    "check-intake-service-mutations.sh",
):
    if stopping:
        sys.exit(143)
    active = subprocess.Popen(
        ["timeout", "-k", "10s", "19m", os.path.join(sys.argv[1], "scripts", script)],
        start_new_session=True,
    )
    if stopping:
        stop(signal.SIGTERM, None)
    status = active.wait()
    signal.alarm(0)
    drained = drain_group(active.pid)
    active = None
    if not drained:
        print("FAIL: child process group did not exit; cache retained", file=sys.stderr)
        sys.exit(125)
    if stopping:
        sys.exit(143)
    if status:
        sys.exit(status if status > 0 else 128 - status)
PY
supervisor=$!
[ "$pending_stop" -eq 0 ] || stop "$pending_stop"
status=0
wait "$supervisor" || status=$?
supervisor=
exit "$status"
