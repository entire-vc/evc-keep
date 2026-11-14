#!/usr/bin/env bash
# Red runs of scripts/check-quickstart.sh: each mutant is a copy of
# docs/quickstart.md with one deliberate defect, and the check must fail on it
# with the message that names that defect. A mutant that passes, or fails for
# another reason, fails this script. The unmutated page must pass first (the
# `quickstart` job runs check-quickstart.sh before this).
#
# Each run starts from a clean host: ~/keep-quickstart removed, database and
# role dropped, the consumer unit gone. It uses the page's own PostgreSQL
# administrator connection (PGHOST, PGUSER=postgres, PGPASSWORD=keep-quickstart).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
doc=$root/docs/quickstart.md
tmp=$(mktemp -d)

# The runs write the CLI's login state and clean the host between runs. They run
# with a HOME of their own, so the developer's real ~/.config/keep and
# ~/keep-quickstart are neither read nor removed. The toolchain caches stay where
# they were, so nothing is downloaded again. A fingerprint of the real config
# directories (HOME's and the inherited XDG_CONFIG_HOME's; names, sizes and checksums,
# compared in memory, never printed) is
# taken before and checked after: the script fails if anything there changed.
export GOCACHE=${GOCACHE:-$(go env GOCACHE)} GOMODCACHE=${GOMODCACHE:-$(go env GOMODCACHE)}
real_home=$HOME
real_xdg=${XDG_CONFIG_HOME:-}
real_state() { # the CLI's config directories of the real user: $HOME/.config/keep and the inherited XDG one
	local d
	for d in "$real_home/.config/keep" ${real_xdg:+"$real_xdg/keep"}; do
		if [ -d "$d" ]; then printf '%s\n' "dir $d"; find "$d" -type f -exec cksum {} + | sort; else printf '%s\n' "none $d"; fi
	done
}
real_before=$(real_state)
mkdir -p "$tmp/home"
export HOME=$tmp/home
# An inherited XDG_CONFIG_HOME wins over HOME for the CLI (cmd/keep/token.go):
# it must not point out of the temporary tree.
unset XDG_CONFIG_HOME
cleanup_run() {
	HOME=$real_home
	find "$tmp" -delete 2>/dev/null || true
}
trap cleanup_run EXIT INT TERM

export PGHOST=${PGHOST:-127.0.0.1} PGUSER=postgres PGPASSWORD=keep-quickstart

reset() {
	find "$HOME/keep-quickstart" -delete 2>/dev/null || true
	find "$HOME/.config" -delete 2>/dev/null || true
	find /run/qs-systemctl -delete 2>/dev/null || true
	find /etc/systemd/system -maxdepth 1 -name keep-quickstart-consumer.service -delete 2>/dev/null || true
	pkill -x keep-server 2>/dev/null || true
	pkill -x keep-runner 2>/dev/null || true
	pkill -f "consumer/server.py" 2>/dev/null || true
	psql -q -c "DROP DATABASE IF EXISTS keep" >/dev/null
	psql -q -c "DROP ROLE IF EXISTS keep" -c "DROP ROLE IF EXISTS keep_app" >/dev/null 2>&1 || true
}

failed=0
# mutant NAME EXPECTED-TEXT PYTHON-REWRITE   (the rewrite edits the variable s)
mutant() {
	name=$1 want=$2 rewrite=$3
	# QS_ONLY (a grep pattern) runs a subset while developing; CI runs them all.
	if [ -n "${QS_ONLY:-}" ] && ! printf '%s\n' "$name" | grep -Eq -- "$QS_ONLY"; then return 0; fi
	m=$tmp/$name.md
	python3 - "$doc" "$m" "$rewrite" <<'PY'
import sys
src, dst, code = sys.argv[1:4]
s = open(src).read()
scope = {"s": s}
exec(code, scope)
if scope["s"] == s:
    sys.exit("the mutation changed nothing")
open(dst, "w").write(scope["s"])
PY
	reset
	log=$tmp/$name.log
	if QUICKSTART_DOC=$m "$root/scripts/check-quickstart.sh" >"$log" 2>&1; then
		echo "NOT RED  $name: the check passed on a page with a deliberate defect"
		failed=1
	elif grep -q -- "$want" "$log"; then
		echo "RED ok   $name: $(grep -m1 -- "$want" "$log" | sed 's/^[[:space:]]*//')"
	else
		echo "WRONG    $name: failed, but without \"$want\"; tail follows"
		tail -15 "$log"
		failed=1
	fi
}

mutant bad-flag 'step audit exited non-zero' \
	's = s.replace("\nkeep audit verify\n", "\nkeep audit verify --no-such-flag\n")'
mutant unmarked-block 'an sh block with no marker' \
	's = s.replace("<!-- quickstart: list-meta -->\n", "")'
mutant deleted-step 'lost the step deploy' \
	'i = s.index("<!-- quickstart: deploy -->"); j = s.index("<!-- quickstart: target -->"); s = s[:i] + s[j:]'
# The outside-policy step: a deploy past the policy must wait for approval (exit
# 3), not be accepted, and must not write the file.
mutant outside-policy-exit-not-3 'step deploy-outside-policy exited non-zero' \
	's = s.replace("--wait 5s --json > \"$QS/outside.json\"", "--wait 5s --json --no-such-flag > \"$QS/outside.json\"")'
mutant outside-policy-file-written 'step deploy-outside-policy exited non-zero' \
	's = s.replace("[ ! -e \"$QS/outside.key\" ]", "touch \"$QS/outside.key\"; [ ! -e \"$QS/outside.key\" ]")'
mutant outside-policy-deleted 'lost the step deploy-outside-policy' \
	'i = s.index("<!-- quickstart: deploy-outside-policy -->"); j = s.index("## 15. The audit journal"); s = s[:i] + s[j:]'
mutant unhealthy-consumer 'step deploy exited non-zero' \
	's = s.replace("\"body_marker\": \"keep-quickstart-ok\"", "\"body_marker\": \"never-served\"")'
mutant value-on-stdout 'value canary found in' \
	'line = "stat -c " + chr(39) + "%a %s %n" + chr(39) + " \"$QS/target/demo.key\""; s = s.replace(line, line + "; cat \"$QS/target/demo.key\"; echo")'
mutant value-base64-on-stdout 'value canary found in' \
	'line = "stat -c " + chr(39) + "%a %s %n" + chr(39) + " \"$QS/target/demo.key\""; s = s.replace(line, line + "; base64 \"$QS/target/demo.key\"")'
mutant value-copied-aside 'value canary found in' \
	'line = "stat -c " + chr(39) + "%a %s %n" + chr(39) + " \"$QS/target/demo.key\""; s = s.replace(line, line + "; cp \"$QS/target/demo.key\" \"$QS/copy.txt\"")'
mutant value-truncated-on-stdout 'value canary found in' \
	'line = "stat -c " + chr(39) + "%a %s %n" + chr(39) + " \"$QS/target/demo.key\""; s = s.replace(line, line + "; head -c 20 \"$QS/target/demo.key\"; echo")'
mutant value-leaked-by-a-failing-step 'a leak search found the value' \
	'line = "stat -c " + chr(39) + "%a %s %n" + chr(39) + " \"$QS/target/demo.key\""; s = s.replace(line, line + "; cat \"$QS/target/demo.key\"; exit 1")'
# The runner log is opened in append mode in this mutant: with a plain ">" the
# runner's next write would overwrite what the step appended.
mutant value-into-runner-log 'value canary found in' \
	's = s.replace("> \"$QS/runner.log\" 2>&1 &", ">> \"$QS/runner.log\" 2>&1 &").replace("\nkeep audit verify\n", "\nkeep audit verify\ncat \"$QS/target/demo.key\" >> \"$QS/runner.log\"\n")'

# Post-run checks. The "target" step prints stat before the checks read it, so
# these defects go in front of the stat line.
LINE='line = "stat -c " + chr(39) + "%a %s %n" + chr(39) + " \"$QS/target/demo.key\""; '
TBL='PGPASSWORD=$(cat \"$QS/db.pw\") psql -h \"${PGHOST:-127.0.0.1}\" -U keep -d keep -q'
mutant target-mode-644 'the target file mode is 644' \
	"$LINE"'s = s.replace(line, "chmod 644 \"$QS/target/demo.key\"; " + line)'
mutant target-size-off 'the target file is' \
	"$LINE"'s = s.replace(line, "printf x >> \"$QS/target/demo.key\"; " + line)'
mutant audit-prints-no-ok 'audit verify did not say ok' \
	's = s.replace("\nkeep audit verify\n", "\necho done\n")'
mutant deploy-answer-not-ok 'the deploy answer is not ok' \
	's = s.replace("--wait 60s --json", "--wait 60s --json | jq \".ok = false\"")'
mutant mcp-meta-is-error 'get_secret_meta over MCP failed' \
	'b = chr(92) + chr(34); s = s.replace("secret_id" + b + ":" + b + "$SECRET_ID", "secret_id" + b + ":" + b + "00000000-0000-0000-0000-000000000000")'
# Other surfaces the value must not reach.
mutant value-on-stderr 'value canary found in' \
	"$LINE"'s = s.replace(line, line + "; cat \"$QS/target/demo.key\" >&2")'
mutant value-into-server-log 'value canary found in' \
	's = s.replace("> \"$QS/server.log\" 2>&1 &", ">> \"$QS/server.log\" 2>&1 &").replace("\nkeep audit verify\n", "\nkeep audit verify\ncat \"$QS/target/demo.key\" >> \"$QS/server.log\"\n")'
mutant value-into-a-table 'value canary found in' \
	"$LINE"'s = s.replace(line, line + "; '"$TBL"' -c \"CREATE TABLE leak(v text)\"; printf \"INSERT INTO leak VALUES (\$\$%s\$\$);\" \"$(cat \"$QS/target/demo.key\")\" | '"$TBL"'")'
# The other three values the run creates: each only in its own file.
mutant db-pw-on-stdout 'db.pw found in' \
	"$LINE"'s = s.replace(line, line + "; cat \"$QS/db.pw\"")'
mutant root-key-on-stdout 'root.key found in' \
	"$LINE"'s = s.replace(line, line + "; cat \"$QS/root.key\"")'
mutant admin-token-on-stdout 'admin.token found in' \
	"$LINE"'s = s.replace(line, line + "; cat \"$QS/admin.token\"")'
# The CLI's config directory (login state) is inside the scan: only the token
# file, only the admin token. Anything else there is a leak.
mutant config-dir-other-file 'value canary found in' \
	"$LINE"'s = s.replace(line, "cp \"$QS/target/demo.key\" \"$XDG_CONFIG_HOME/keep/other\"; " + line)'
# Appended after the last keep call: an earlier append would break the token and
# fail the audit step for another reason.
mutant db-pw-in-cli-token 'db.pw found in' \
	's = s.replace("\nkeep audit verify\n", "\nkeep audit verify\ncat \"$QS/db.pw\" >> \"$XDG_CONFIG_HOME/keep/token\"\n")'
mutant admin-token-in-cli-other-file 'admin.token found in' \
	"$LINE"'s = s.replace(line, "cp \"$QS/admin.token\" \"$XDG_CONFIG_HOME/keep/token.bak\"; " + line)'
mutant login-to-real-home 'QS_CLI_TOKEN_FILE does not hold' \
	's = s.replace("export XDG_CONFIG_HOME=\"$QS/config\"\n", "")'
# A copy of the login state outside the run directory (the run's own HOME, not
# under $QS) is found too: the scan also covers $HOME/.config/keep when it exists.
mutant admin-token-in-real-home 'admin.token found in' \
	"$LINE"'s = s.replace(line, "mkdir -p \"$HOME/.config/keep\"; cp \"$QS/admin.token\" \"$HOME/.config/keep/token\"; " + line)'
# The page itself: modes outside the allowlists.
mutant ci-skip-on-a-real-step 'only clone, database and drop-database may be' \
	's = s.replace("<!-- quickstart: list-meta -->", "<!-- quickstart: list-meta ci-skip -->")'
mutant human-on-a-real-step 'only open-link may be' \
	's = s.replace("<!-- quickstart: list-meta -->", "<!-- quickstart: list-meta human -->")'
mutant unknown-mode 'unknown mode' \
	's = s.replace("<!-- quickstart: list-meta -->", "<!-- quickstart: list-meta skipme -->")'

# The consumer's health depends on the delivered file, and the runner's right
# to restart the unit is on the page.
mutant consumer-reads-the-wrong-file 'step deploy exited non-zero' \
	's = s.replace("server.py $QS/target/demo.key", "server.py $QS/target/other.key")'
mutant deleted-restart-permission 'lost the step restart-permission' \
	'i = s.index("<!-- quickstart: restart-permission -->"); j = s.index("## 12. The host policy"); s = s[:i] + s[j:]'

reset
[ "$(real_state)" = "$real_before" ] || { echo "FAIL quickstart red runs: the real ~/.config/keep changed during the run" >&2; failed=1; }
[ "$failed" -eq 0 ] || { echo "FAIL quickstart red runs" >&2; exit 1; }
echo "PASS quickstart red runs"
