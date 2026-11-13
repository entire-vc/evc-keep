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
trap 'find "$tmp" -delete' EXIT INT TERM

export PGHOST=${PGHOST:-127.0.0.1} PGUSER=postgres PGPASSWORD=keep-quickstart

reset() {
	find "$HOME/keep-quickstart" -delete 2>/dev/null || true
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
[ "$failed" -eq 0 ] || { echo "FAIL quickstart red runs" >&2; exit 1; }
echo "PASS quickstart red runs"
