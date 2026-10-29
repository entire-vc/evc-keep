#!/bin/sh
# Proves the lane poller tests can fail: in a scratch copy of the tree, switch
# off one property of plugins/mesh/lanepoller (and its command) at a time and
# require the tests to go red. A property whose removal leaves the tests green
# is not tested. Exits 0 only if every mutation is caught.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
src=plugins/mesh/lanepoller/poller.go
tdir=plugins/mesh tpkg="./lanepoller/ ./cmd/keep-lane-poller/"

fail=0
# mutate NAME PYTHON: PYTHON edits the string t (a copy of the source s).
mutate() {
	name=$1 prog=$2
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! SRC="$work/tree/$src" PROG="$prog" python3 -I -c '
import os
p = os.environ["SRC"]
s = open(p).read()
t = s
exec(os.environ["PROG"])
if t == s:
    raise SystemExit(1)
open(p, "w").write(t)'; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree/$tdir" && go test -timeout 120s -count=1 $tpkg >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

# The unmutated packages must be green, or every red below proves nothing.
mutation_apply_only || (cd "$root/$tdir" && go test -timeout 120s -count=1 $tpkg >"$work/base" 2>&1) || { echo "FAIL baseline is red"; exit 1; }

mutate allowlist-dropped 't=s.replace("	if !slices.Contains(p.cfg.Allow, r.Lane) {", "	if !slices.Contains(p.cfg.Allow, r.Lane) && false {",1)'
mutate allowlist-empty-lane-only 't=s.replace("	if !slices.Contains(p.cfg.Allow, r.Lane) {", "	if !slices.Contains(p.cfg.Allow, r.Lane) && r.Lane == \"\" {",1)'
mutate log-token 't=s.replace("	resp, err := p.cfg.HTTP.Do(req)\n", "	p.cfg.Log.Info(\"auth\", \"token\", p.cfg.Token)\n	resp, err := p.cfg.HTTP.Do(req)\n",1)'
mutate log-claim-token 't=s.replace("\"fingerprint\", shapedBy(fingerprint.Valid, r.Fingerprint))", "\"fingerprint\", shapedBy(fingerprint.Valid, r.Fingerprint), \"claim\", r.ClaimToken)",1)'
mutate error-carries-body 't=s.replace("		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))\n		return fmt.Errorf(\"%s: status %d\", path, resp.StatusCode)", "		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))\n		return fmt.Errorf(\"%s: status %d: %s\", path, resp.StatusCode, b)",1)'
mutate transport-error-text 't=s.replace("return fmt.Errorf(\"%s: %s\", path, transportCategory(ctx, err))", "return fmt.Errorf(\"%s: %s: %w\", path, transportCategory(ctx, err), err)",1)'
mutate exit-code-ignored 't=s.replace("	if err != nil || code != 0 {\n		return ResultFailed", "	if err != nil {\n		return ResultFailed",1)'
mutate unrecognised-output-ok 't=s.replace("	return ResultFailed // exit 0 with unrecognised output", "	return ResultOK // exit 0 with unrecognised output",1)'
mutate follow-redirects 't=s.replace("	cfg.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }\n", "",1)'
mutate loop-stops-on-error 't=s.replace("			p.cfg.Log.Warn(\"poll failed\", \"err\", err.Error())\n", "			p.cfg.Log.Warn(\"poll failed\", \"err\", err.Error())\n			return\n",1)'
mutate env-inherited 't=s.replace("	cmd.Env = []string{\"PATH=/usr/bin:/bin:/opt/homebrew/bin\", \"HOME=\" + homeOf()}\n", "",1)'
mutate script-relative-accepted 't=s.replace("	if !filepath.IsAbs(cfg.Script) || filepath.Clean(cfg.Script) != cfg.Script {", "	if filepath.IsAbs(\"\") {",1)'
mutate server-fields-unshaped 't=s.replace("	if ok(v) {", "	if ok != nil {",1)'
mutate claim-token-unchecked 't=s.replace("	if !tokRe.MatchString(r.ClaimToken) {", "	if false {",1)'
mutate bad-request-id-run 't=s.replace("		p.cfg.Log.Warn(\"bad request id, ignored\")\n		return nil", "		p.cfg.Log.Warn(\"bad request id, ignored\")",1)'
mutate lane-logged-unshaped 't=s.replace("\"lane\", shaped(laneRe, r.Lane)", "\"lane\", r.Lane",1)'
src=plugins/mesh/cmd/keep-lane-poller/main.go
mutate token-file-group-readable 't=s.replace("fi.Mode().Perm()&^0o600 != 0", "fi.Mode().Perm()&0o007 != 0",1)'
mutate token-file-owner-exec 't=s.replace("fi.Mode().Perm()&^0o600 != 0", "fi.Mode().Perm()&0o077 != 0",1)'
mutate token-file-error-echoes-content 't=s.replace("return \"\", fmt.Errorf(\"token file must be a single KEEP_POLLER_TOKEN=<token> line or the bare token\")", "return \"\", fmt.Errorf(\"token file must be a single KEEP_POLLER_TOKEN=<token> line or the bare token, got %q\", c)",1)'
mutate started-logs-token 't=s.replace("log.Info(\"started\", \"lanes\"", "log.Info(\"started\", \"token\", token, \"lanes\"",1)'
exit $fail
