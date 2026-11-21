#!/bin/sh
# Sourced by checks that intentionally crash child processes. Go's t.TempDir
# cleanup cannot run after os.Exit, a runtime fatal error, or a process kill.
# Keep child scratch files outside the copied source tree but inside the
# shell-owned workspace, so the parent removes them even after a child dies.
temp_workspace() {
	work=$(mktemp -d "${TMPDIR:-/tmp}/keep-check.XXXXXXXX")
	work=$(cd "$work" && pwd)
	trap 'temp_workspace_cleanup $?' EXIT
	trap 'exit 129' HUP
	trap 'exit 130' INT
	trap 'exit 143' TERM
	mkdir "$work/tmp"
	TMPDIR="$work/tmp"
	export TMPDIR
}

temp_workspace_cleanup() {
	# Preserve the check's verdict, including its signal exit code. Report a
	# cleanup error instead of letting set -e replace that verdict silently.
	cleanup_status=$1
	trap - EXIT
	# A mutation suite prints its snapshot summary and checks that the source
	# did not change during the run; a change there turns a green run red.
	if command -v mutation_snapshot_report >/dev/null 2>&1; then
		if ! mutation_snapshot_report "$cleanup_status" && [ "$cleanup_status" -eq 0 ]; then
			cleanup_status=2
		fi
	fi
	# Mutation checks may also own a private Go cache outside this workspace.
	# Run its cleanup before removing scratch, preserving the original verdict.
	if command -v gocache_cleanup >/dev/null 2>&1; then
		gocache_cleanup
	fi
	if ! rm -rf "$work"; then
		echo 'WARNING: temporary workspace cleanup failed' >&2
	fi
	exit "$cleanup_status"
}
