#!/bin/sh
# A crashing test process cannot run t.Cleanup. Its parent must own its files.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
for check in "$root"/scripts/check-*-mutations.sh "$root/scripts/check-import-boundaries.sh"; do
	if ! awk '
		/^[[:space:]]*\.[[:space:]]+"\$root\/scripts\/temp-workspace\.sh"[[:space:]]*$/ { sourced = 1; next }
		sourced && /^[[:space:]]*temp_workspace[[:space:]]*$/ { called = 1 }
		END { exit !(sourced && called) }
	' "$check"; then
		echo "FAIL $(basename "$check"): workspace helper must be sourced and called"
		exit 1
	fi
	echo "ok   $(basename "$check"): workspace helper sourced and called"
done
# Check the shell that owns the workspace, not just this script's shell.
# macOS sh runs EXIT traps on signals even without explicit signal traps;
# dash and Alpine ash need those traps to remove the workspace.
shells='sh dash'
if [ "${TEMP_WORKSPACE_REQUIRE_ASH:-0}" = 1 ] || [ -f /etc/alpine-release ]; then
	shells="$shells ash"
fi
for shell in $shells; do
	if ! command -v "$shell" >/dev/null 2>&1; then
		echo "FAIL $shell: required workspace shell is unavailable"
		exit 1
	fi
done
probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$probe/outer"
cat >"$probe/crash_test.go" <<'GO'
package scratch

import (
	"os"
	"testing"
)

func TestScratch(t *testing.T) {
	want := os.Getenv("SCRATCH_TMPDIR")
	if want == "" || os.Getenv("TMPDIR") != want {
		t.Fatal("child process did not inherit workspace TMPDIR")
	}
	_ = t.TempDir()
	switch os.Getenv("SCRATCH_MODE") {
	case "panic":
		go func() { panic("deliberate cleanup probe") }()
		select {}
	case "exit":
		os.Exit(23)
	case "failure":
		t.Fatal("deliberate cleanup probe")
	}
}
GO
go test -c -o "$probe/crash.test" "$probe/crash_test.go"

for shell in $shells; do
	for mode in success failure panic exit HUP INT TERM; do
		case "$mode" in
			success) want=0 ;;
			failure) want=1 ;;
			panic) want=2 ;;
			exit) want=23 ;;
			HUP) want=129 ;;
			INT) want=130 ;;
			TERM) want=143 ;;
		esac
		got=0
		env -u TMPDIR SCRATCH_MODE="$mode" "$shell" -c '
			set -eu
			TMPDIR="$2/outer"
			. "$1/scripts/temp-workspace.sh"
			temp_workspace
			case "$SCRATCH_MODE" in
				HUP|INT|TERM)
					mkdir "$TMPDIR/signal-probe"
					kill -s "$SCRATCH_MODE" "$$"
					exit 99 ;;
				*) SCRATCH_TMPDIR="$TMPDIR" "$2/crash.test" ;;
			esac
		' "$shell" "$root" "$probe" >"$probe/output" 2>&1 || got=$?
		if [ "$got" -ne "$want" ]; then
			echo "FAIL $shell/$mode: exit $got, want $want"
			exit 1
		fi
		if [ -n "$(ls -A "$probe/outer")" ]; then
			echo "FAIL $shell/$mode: temporary files survived their owner"
			exit 1
		fi
		echo "ok   $shell/$mode: exit $want, no temporary files"
	done
done
