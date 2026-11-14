#!/usr/bin/env bash
# The quickstart as an executable check: extracts the blocks of
# docs/quickstart.md marked `<!-- quickstart: ID [MODE] -->` and runs each one
# verbatim, in order, in its own bash (-euo pipefail), from the repository
# root. Nothing runs that the page does not contain, except:
#   - the person typing the value: test/e2e/human.mjs drives a headless
#     browser to the link the `open-link` block printed and types a random
#     canary into the page;
#   - the checks after the run (below);
#   - the three blocks marked ci-skip, which need Docker or the user's home
#     (the container this runs in has no Docker: PostgreSQL is a job service).
# Checks: the canary is in the target file and nowhere else (the step outputs,
# both logs, the journal and every table: test/quickstart/leak_test.go); the
# deploy answer says ok with a healthy consumer; the fingerprint is the same on
# the page, in `keep version` and in the deploy answer; the file's size is the
# value's length; the audit chain verifies. Every guard has a red run in
# scripts/check-quickstart-redruns.sh.
#
# QUICKSTART_DOC overrides the page (the red runs use it). The run refuses to
# start if ~/keep-quickstart exists: it would be written over.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
doc=${QUICKSTART_DOC:-$root/docs/quickstart.md}

fail() { echo "FAIL quickstart: $1" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail "needs a Linux host (stat -c, systemd)"
for c in node psql jq curl openssl python3 sudo systemctl make go git; do
	command -v "$c" >/dev/null 2>&1 || fail "$c is required"
done
if [ -z "${CHROME_BIN:-}" ]; then
	for c in /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome; do
		[ -x "$c" ] && CHROME_BIN=$c && break
	done
fi
[ -n "${CHROME_BIN:-}" ] || fail "headless Chromium is required"
export CHROME_BIN
[ "$(id -u)" -eq 0 ] && export KEEP_E2E_NO_SANDBOX=1
[ -f "$doc" ] || fail "$doc does not exist"
qs=$HOME/keep-quickstart
[ ! -e "$qs" ] || fail "$qs exists; remove it first, this run would overwrite it"

work=$(mktemp -d)
secrets=$(mktemp -d)
steps=$work/steps
out=$work/out
mkdir -p "$steps" "$out"

cleanup() {
	for p in "$qs/runner.pid" "$qs/server.pid"; do
		[ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true
	done
	systemctl stop keep-quickstart-consumer 2>/dev/null || true
	find "$secrets" -delete 2>/dev/null || true
	find "$work" -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---- extract the marked blocks ------------------------------------------------
awk -v dir="$steps" '
function bad(msg) { print "FAIL quickstart: " FILENAME ":" NR ": " msg > "/dev/stderr"; failed = 1; exit 1 }
/^<!-- quickstart: / {
	if (id != "") bad("marker " id " has no block")
	if (match($0, /^<!-- quickstart: [a-z0-9-]+( [a-z-]+)? -->$/) == 0) bad("malformed marker")
	line = $0; sub(/^<!-- quickstart: /, "", line); sub(/ -->$/, "", line)
	n = split(line, parts, " "); id = parts[1]; mode = (n > 1 ? parts[2] : "run")
	if (id in seen) bad("duplicate step " id)
	seen[id] = 1
	next
}
/^```(sh|bash)$/ {
	if (id == "") bad("an sh block with no marker: a command the check would never run")
	count++; file = sprintf("%s/%02d-%s", dir, count, id)
	printf "" > (file ".sh"); print mode > (file ".mode"); close(file ".mode")
	infence = 1; next
}
/^```/ {
	if (infence) { close(file ".sh"); infence = 0; id = ""; next }
	if (id != "") bad("marker " id " is followed by a block that is not sh")
	next
}
infence { print > (file ".sh"); next }
END { if (!failed && (id != "" || infence)) { print "FAIL quickstart: unterminated marker or block" > "/dev/stderr"; exit 1 } }
' "$doc"

ls "$steps"/*.sh >/dev/null 2>&1 || fail "the page has no marked block"
for need in build migrate server-start bootstrap-org create-ref input-link open-link list-meta mcp consumer restart-permission runner-enroll runner-start deploy-policy deploy deploy-outside-policy audit cleanup; do
	ls "$steps"/*-"$need".sh >/dev/null 2>&1 || fail "the page lost the step $need"
done
for f in "$steps"/*.mode; do
	id=$(basename "$f" .mode); id=${id#*-}
	case "$(cat "$f")" in
	run) ;;
	ci-skip) case "$id" in clone | database | drop-database) ;; *) fail "step $id is marked ci-skip: only clone, database and drop-database may be" ;; esac ;;
	human) [ "$id" = open-link ] || fail "step $id is marked human: only open-link may be" ;;
	*) fail "step $id has an unknown mode $(cat "$f")" ;;
	esac
done

leak_scan() { # leak_scan partial|full: 0 if clean (partial: no positive controls)
	QS_PARTIAL=$([ "$1" = partial ] && echo 1 || echo 0) QS_CANARY_FILE="$secrets/canary" QS_TARGET="$qs/target/demo.key" QS_SCAN="$out:$qs$([ -d "$HOME/.config/keep" ] && printf %s ":$HOME/.config/keep")" \
		QS_DB_PW_FILE="$qs/db.pw" QS_ROOT_KEY_FILE="$qs/root.key" QS_ADMIN_TOKEN_FILE="$qs/admin.token" QS_SERVER_ENV="$qs/keep-server.env" QS_CLI_TOKEN_FILE="$qs/config/keep/token" \
		go test -tags quickstart -count=1 -v -run 'TestScanCanFail|TestRawFetchCanFail|TestQuickstartNoLeak' ./test/quickstart >"$work/go-test.log" 2>&1
}

# The raw answers of the server's API, as a client would get them: the CLI
# prints only the fields it knows, a field it dropped would hide a leak. Asked
# while the server is up, so before the clean-up step stops it.
raw_scan() {
	local env_sh="$qs/env.sh" org sid
	org=$(. "$env_sh" && printf '%s' "$KEEP_ORG"); sid=$(. "$env_sh" && printf '%s' "$SECRET_ID")
	QS_CANARY_FILE="$secrets/canary" QS_DB_PW_FILE="$qs/db.pw" QS_ROOT_KEY_FILE="$qs/root.key" QS_ADMIN_TOKEN_FILE="$qs/admin.token" QS_SERVER_ENV="$qs/keep-server.env" QS_TARGET="$qs/target/demo.key" QS_TOKEN_FILE="$qs/admin.token" QS_SERVER=$(. "$env_sh" && printf '%s' "$KEEP_SERVER") \
		QS_RAW_PATHS="/orgs/$org/secrets?scope_level=org&scope_id=$org /orgs/$org/secrets/$sid /orgs/$org/secrets/$sid/versions /v1/deployments/$(jq -r .request_id "$out/deploy.out") /v1/input-links/$(jq -r .request_id "$qs/link.json")" \
		go test -tags quickstart -count=1 -v -run 'TestRawAnswersNoLeak' ./test/quickstart >"$work/go-raw.log" 2>&1 \
		&& grep -q -- '--- PASS: TestRawAnswersNoLeak' "$work/go-raw.log" \
		|| { grep -E '^\s*(---|FAIL|ok|leak_test)' "$work/go-raw.log" || true; fail "a raw API answer carries the value, or could not be fetched (no value is printed)"; }
}

# ---- run -----------------------------------------------------------------------
canary="kc$(openssl rand -hex 12)-v1-secret"
printf '%s' "$canary" >"$secrets/canary"
chmod 600 "$secrets/canary"
human_out=

for f in "$steps"/*.sh; do
	base=$(basename "$f" .sh); id=${base#*-}
	mode=$(cat "$steps/$base.mode")
	if [ "$mode" = ci-skip ]; then echo "== $id: skipped (ci-skip)"; continue; fi
	echo "== $id"
	[ "$id" = cleanup ] && raw_scan
	if ! bash -euo pipefail "$f" >"$out/$id.out" 2>"$out/$id.err"; then
		# A failing step may carry a leak in its error: search before anything is printed.
		leak_scan partial || fail "step $id exited non-zero and a leak search found the value; nothing is printed"
		echo "--- stdout"; cat "$out/$id.out"; echo "--- stderr"; cat "$out/$id.err"
		for l in server runner; do [ -f "$qs/$l.log" ] && { echo "--- $l.log"; tail -20 "$qs/$l.log"; }; done
		fail "step $id exited non-zero"
	fi
	if [ "$mode" = human ]; then
		human_out=$(jq -n --arg url "$(jq -r .url "$qs/link.json")" --rawfile plaintext "$secrets/canary" '{url:$url,plaintext:$plaintext}' | node test/e2e/human.mjs) \
			|| fail "the person's step (headless browser) failed"
		printf '%s' "$human_out" >"$out/human-page.json"
		echo "page showed: $human_out"
	fi
done

# ---- checks ----------------------------------------------------------------------
[ -n "$human_out" ] || fail "the person's step never ran"
jq -e '.ok == true and .healthcheck.status == "ok"' "$out/deploy.out" >/dev/null || fail "the deploy answer is not ok with a healthy consumer"
page_fp=$(jq -r .fingerprint "$out/human-page.json")
[ -n "$page_fp" ] || fail "the page showed no fingerprint"
deploy_fp=$(jq -r .fingerprint "$out/deploy.out")
[ "$page_fp" = "$deploy_fp" ] || fail "the fingerprint on the page differs from the deploy answer"
grep -q -- "$page_fp" "$out/list-meta.out" || fail "keep version does not show the fingerprint the page showed"
read -r mode size _ <"$out/target.out"
[ "$mode" = 600 ] || fail "the target file mode is $mode, not 600"
[ "$size" = "${#canary}" ] || fail "the target file is $size bytes, the typed value is ${#canary}"
grep -Eq "(^|[[:space:]])${#canary}([[:space:]]|$)" "$out/list-meta.out" || fail "keep version does not show the value's length"
grep -q '^ok:[[:space:]]*true' "$out/audit.out" || fail "audit verify did not say ok"
jq -e 'select(.id == 3) | .result.isError == false' "$out/mcp.out" >/dev/null || fail "get_secret_meta over MCP failed"

# ---- what to search -----------------------------------------------------------------
export PGPASSWORD
PGPASSWORD=$(cat "$qs/db.pw")
dbq() { psql -h "${PGHOST:-127.0.0.1}" -U keep -d keep -Atc "$1"; }
dbq "SELECT to_jsonb(a) FROM audit_records a ORDER BY org_seq" >"$out/journal.json"
: >"$out/tables.json"
for t in $(dbq "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"); do
	dbq "SELECT to_jsonb(x) FROM \"$t\" x" >>"$out/tables.json"
done
[ -s "$out/journal.json" ] || fail "the journal dump is empty: the leak search had nothing to look at"

log=$work/go-test.log
if ! leak_scan full; then
	grep -E '^\s*(---|FAIL|ok|leak_test)' "$log" || true
	fail "the leak search failed (file names above; no value is printed)"
fi
grep -q -- '--- SKIP' "$log" && fail "a leak test was skipped; SKIP is not PASS"
grep -q -- '--- PASS: TestQuickstartNoLeak' "$log" || fail "TestQuickstartNoLeak did not run"
for f in "$steps"/*.sh; do b=$(basename "$f" .sh); id=${b#*-}; [ -f "$out/$id.out" ] && { echo "== $id"; cat "$out/$id.out"; }; done
echo "PASS quickstart"
