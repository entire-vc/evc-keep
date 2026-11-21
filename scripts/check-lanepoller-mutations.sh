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
	mutation_snapshot "$work/tree"
	if ! SRC="$work/tree/$src" PROG="$prog" NAME="$name" LIB="$root/scripts/lib" python3 -I -c '
import os, sys
sys.path.insert(0, os.environ["LIB"])
from mutation_edit import named_edit
p = os.environ["SRC"]
def edit(text, old, new, occurrence=None):
    return named_edit(os.environ["NAME"], text, old, new, occurrence, p)
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

mutate allowlist-dropped 't=edit(s, "	if !slices.Contains(p.cfg.Allow, r.Lane) {", "	if !slices.Contains(p.cfg.Allow, r.Lane) && false {")'
mutate allowlist-empty-lane-only 't=edit(s, "	if !slices.Contains(p.cfg.Allow, r.Lane) {", "	if !slices.Contains(p.cfg.Allow, r.Lane) && r.Lane == \"\" {")'
mutate log-token 't=edit(s, "	resp, err := p.cfg.HTTP.Do(req)\n", "	p.cfg.Log.Info(\"auth\", \"token\", p.cfg.Token)\n	resp, err := p.cfg.HTTP.Do(req)\n")'
mutate log-claim-token 't=edit(s, "\"fingerprint\", shapedBy(fingerprint.Valid, r.Fingerprint))", "\"fingerprint\", shapedBy(fingerprint.Valid, r.Fingerprint), \"claim\", r.ClaimToken)")'
mutate error-carries-body 't=edit(s, "		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))\n		return fmt.Errorf(\"%s: status %d\", path, resp.StatusCode)", "		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))\n		return fmt.Errorf(\"%s: status %d: %s\", path, resp.StatusCode, b)")'
mutate transport-error-text 't=edit(s, "return fmt.Errorf(\"%s: %s\", path, transportCategory(ctx, err))", "return fmt.Errorf(\"%s: %s: %w\", path, transportCategory(ctx, err), err)")'
mutate exit-code-ignored 't=edit(s, "	if err != nil || code != 0 {\n		return ResultFailed", "	if err != nil {\n		return ResultFailed")'
mutate unrecognised-output-ok 't=edit(s, "	return ResultFailed // exit 0 with unrecognised output", "	return ResultOK // exit 0 with unrecognised output")'
mutate follow-redirects 't=edit(s, "	cfg.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }\n", "")'
mutate loop-stops-on-error 't=edit(s, "			p.cfg.Log.Warn(\"poll failed\", \"err\", err.Error())\n", "			p.cfg.Log.Warn(\"poll failed\", \"err\", err.Error())\n			return\n")'
mutate env-inherited 't=edit(s, "	cmd.Env = []string{\"PATH=/usr/bin:/bin:/opt/homebrew/bin\", \"HOME=\" + homeOf()}\n", "")'
mutate script-relative-accepted 't=edit(s, "	if !filepath.IsAbs(cfg.Script) || filepath.Clean(cfg.Script) != cfg.Script {", "	if filepath.IsAbs(\"\") {")'
mutate server-fields-unshaped 't=edit(s, "	if ok(v) {", "	if ok != nil {")'
mutate claim-token-unchecked 't=edit(s, "	if !tokRe.MatchString(r.ClaimToken) {", "	if false {")'
mutate bad-request-id-run 't=edit(s, "		p.cfg.Log.Warn(\"bad request id, ignored\")\n		return nil", "		p.cfg.Log.Warn(\"bad request id, ignored\")")'
mutate lane-logged-unshaped 't=edit(s, "\"lane\", shaped(laneRe, r.Lane)", "\"lane\", r.Lane")'
mutate remote-plain-http-accepted 't=edit(s, "u.Scheme == \"http\" && isLoopback(u.Hostname())", "u.Scheme == \"http\"")'
mutate empty-token-accepted 't=edit(s, "	if cfg.Token == \"\" {", "	if false {")'
mutate empty-allowlist-accepted 't=edit(s, "	if len(cfg.Allow) == 0 {", "	if false {")'
mutate allowlist-entry-unvalidated 't=edit(s, "		if !laneRe.MatchString(l) {", "		if len(l) < 0 {")'
mutate nothing-running-reported-ok 't=edit(s, "	if nothing {\n		return ResultNothingRunning", "	if nothing {\n		return ResultOK")'
mutate bearer-header-dropped 't=edit(s, "	req.Header.Set(\"Authorization\", \"Bearer \"+p.cfg.Token)\n", "")'
src=plugins/mesh/cmd/keep-lane-poller/main.go
mutate token-file-group-readable 't=edit(s, "fi.Mode().Perm()&^0o600 != 0", "fi.Mode().Perm()&0o007 != 0")'
mutate token-file-owner-exec 't=edit(s, "fi.Mode().Perm()&^0o600 != 0", "fi.Mode().Perm()&0o077 != 0")'
mutate token-file-error-echoes-content 't=edit(s, "return \"\", fmt.Errorf(\"token file must be a single KEEP_POLLER_TOKEN=<token> line or the bare token\")", "return \"\", fmt.Errorf(\"token file must be a single KEEP_POLLER_TOKEN=<token> line or the bare token, got %q\", c)")'
mutate started-logs-token 't=edit(s, "log.Info(\"started\", \"lanes\"", "log.Info(\"started\", \"token\", token, \"lanes\"")'
exit $fail
