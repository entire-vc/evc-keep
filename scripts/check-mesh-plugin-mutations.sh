#!/bin/sh
# Proves the Mesh plugin tests can fail: in a scratch copy of the tree, switch
# off one property of plugins/mesh/mesh.go at a time and require the plugin
# tests to go red. A property whose removal leaves the tests green is not
# tested. Exits 0 only if every mutation is caught. MUTATION_SHARD_INDEX and
# MUTATION_SHARD_TOTAL select every N-th mutation; each shard runs the
# baseline itself, since it is cheap and a shard must not trust another.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
mutation_shard_init
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
src=plugins/mesh/mesh.go
tdir=plugins/mesh tpkg=./...

fail=0
# mutate NAME PYTHON: PYTHON edits the string t (a copy of the source s).
mutate() {
	mutation_selected || return 0
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

# The unmutated module must be green, or every red below proves nothing.
# What a red baseline may print: failing test names, package lines and a panic
# count. Test output can carry token canaries, so it never reaches the CI log.
baseline_names() {
	# Only a captured name survives: the tail of a line is never printed.
	sed -nE \
		-e 's/^--- FAIL: (Test[A-Za-z0-9_]*(\/[A-Za-z0-9_.-]+)*)([[:space:]].*)?$/--- FAIL: \1/p' \
		-e 's/^(FAIL|ok)[[:space:]]+(github\.com\/entire-vc\/evc-keep[A-Za-z0-9_.\/-]*)([[:space:]].*)?$/\1 \2/p' "$1" | cut -c1-160
	grep -c '^panic:' "$1" | sed 's/^/panics: /'
}

# The filter must keep the failing test name and package, and drop every other
# byte of a line: indented output, a panic, and raw lines that merely start
# with FAIL/ok or look like a test or package line with a canary after it.
{
	printf -- '--- FAIL: TestX (0.00s)\n    x_test.go:1: leaked CANARY-7\n'
	printf -- 'FAIL\tgithub.com/entire-vc/evc-keep/plugins/mesh\t0.1s\n'
	printf -- 'panic: CANARY-7\n'
	printf -- 'FAIL TOKEN_CANARY-8\nok TOKEN_CANARY-9\nFAIL\n'
	printf -- 'FAIL github.com/entire-vc/evc-keep/x CANARY-10\n'
	printf -- '--- FAIL: TOKEN_CANARY-11\n--- FAIL: TestY CANARY-12\n'
} >"$work/fixture"
baseline_names "$work/fixture" >"$work/fixture.out"
if grep -q CANARY "$work/fixture.out" || ! grep -q -- '^--- FAIL: TestX$' "$work/fixture.out" ||
	! grep -q -- '^FAIL github.com/entire-vc/evc-keep/plugins/mesh$' "$work/fixture.out"; then
	echo "FAIL baseline diagnostic filter leaks test output or drops test names"
	exit 1
fi

mutation_apply_only || (cd "$root/plugins/mesh" && go test -timeout 120s -count=1 ./... >"$work/base" 2>&1) || { echo "FAIL baseline is red"; baseline_names "$work/base"; exit 1; }

mutate log-response-body 't=edit(s, '\''	var a issueAnswer'\'', '\''	p.log.Debug("resp", "body", string(body))\n	var a issueAnswer'\'')'
mutate forward-error-body 't=edit(s, '\''	clear(body)\n	switch resp.StatusCode {'\'', '\''	return nil, errors.New(string(body))\n	switch resp.StatusCode {'\'')'
mutate no-keyid-validation 't=edit(edit(s, '\''if !rotation.ValidKeyID(keyID) {'\'', '\''if false {'\'', 2), '\''if !rotation.ValidKeyID(keyID) {'\'', '\''if false {'\'', 1)'
mutate dualkey-false 't=edit(s, '\''DualKey: true'\'', '\''DualKey: false'\'')'
mutate current-multi-active 't=edit(s, '\''			return "", false, nil\n		}\n		id = k.KeyID'\'', '\''		}\n		id = k.KeyID'\'')'
mutate accept-empty-value 't=edit(s, '\''|| a.Key == ""'\'', '\'''\'')'
mutate token-string 't=edit(edit(s, '\''func (Token) String() string { return secret.Redacted }'\'', '\''func (t Token) String() string { return string(t) }'\''), '\''func (Token) GoString() string { return secret.Redacted }'\'', '\''func (t Token) GoString() string { return string(t) }'\'')'
mutate token-marshal 't=edit(edit(s, '\''return []byte(secret.Redacted), nil'\'', '\''return []byte(string(t)), nil'\''), '\''func (Token) MarshalText'\'', '\''func (t Token) MarshalText'\'')'
mutate provider-string 't=edit(edit(s, '\''func (Provider) String() string   { return "mesh.Provider" }'\'', '\'''\''), '\''func (Provider) GoString() string { return "mesh.Provider" }'\'', '\'''\'')'
mutate plain-http-off-loopback 't=edit(s, '\''(u.Scheme != "http" || !loopback(u.Hostname()))'\'', '\''false'\'')'
mutate orphan-key-kept 't=edit(s, '\''			p.revokeOrphan(ctx, a.KeyID, before)'\'', '\''			_ = before'\'')'
mutate log-token 't=edit(s, '\''	resp, err := p.hc.Do(r)\n'\'', '\''	p.log.Info("auth", "token", string(p.token))\n	resp, err := p.hc.Do(r)\n'\'')'
mutate log-transport-error 't=edit(s, '\''	resp, err := p.hc.Do(r)\n	if err != nil {\n'\'', '\''	resp, err := p.hc.Do(r)\n	if err != nil {\n		p.log.Warn(err.Error())\n'\'')'
mutate log-list-body 't=edit(s, '\''	var a struct {\n		Keys'\'', '\''	p.log.Debug("list", "body", string(body))\n	var a struct {\n		Keys'\'')'
mutate issue-accept-bad-keyid 't=edit(s, '\''derr != nil || !rotation.ValidKeyID(a.KeyID) ||'\'', '\''derr != nil ||'\'')'
mutate list-accept-bad-keyid 't=edit(s, "if (k.KeyID != primaryKeyID && !rotation.ValidKeyID(k.KeyID)) ||", "if (k.KeyID != primaryKeyID && !rotation.ValidKeyID(k.KeyID) && k.KeyID == \"\") ||")'
mutate list-accept-prefix-primary 't=edit(s, "if (k.KeyID != primaryKeyID && !rotation.ValidKeyID(k.KeyID)) ||", "if (!strings.HasPrefix(k.KeyID, \"p\") && !rotation.ValidKeyID(k.KeyID)) ||")'
# The original key "primary" under its per-agent alias (PrimaryAlias).
mutate current-primary-not-current 't=edit(s, "		if id == primaryKeyID {\n			id = p.alias\n		}", "		if id == primaryKeyID {\n			return \"\", false, nil\n		}")'
mutate current-primary-raw 't=edit(s, "		if id == primaryKeyID {\n			id = p.alias\n		}", "")'
mutate alias-field-unset 't=edit(s, "alias: PrimaryAlias(cfg.AgentID), ", "")'
mutate meshid-noop 't=edit(s, "	if keyID == p.alias {\n		return primaryKeyID\n	}\n", "")'
mutate revoke-alias-unmapped 't=edit(s, "\"/\"+p.meshID(keyID)", "\"/\"+keyID")'
mutate revoke-404-listed-without-alias 't=edit(s, "case listed(keys, p.meshID(keyID)):", "case listed(keys, keyID):")'
mutate check-alias-unmapped 't=edit(s, "	want := p.meshID(keyID)", "	want := keyID")'
mutate list-accept-alias-collision 't=edit(s, ") || k.KeyID == p.alias {", ") {")'
mutate issue-accept-alias 't=edit(s, " || a.KeyID == p.alias || a.Key == \"\"", " || a.Key == \"\"")'
mutate alias-namespace-changed 't=edit(s, "ef80de33-2cb0-4dca-a3ac-c90cf2012f14", "ef80de33-2cb0-4dca-a3ac-c90cf2012f15")'
mutate alias-not-per-agent 't=edit(s, "[]byte(agentID+\"/\"+primaryKeyID)", "[]byte(primaryKeyID)")'
mutate leak-primary-error-body 't=edit(s, "	clear(body)\n	switch resp.StatusCode {", "	if strings.HasSuffix(r.URL.Path, \"/primary\") {\n		return nil, errors.New(string(body))\n	}\n	clear(body)\n	switch resp.StatusCode {")'
mutate active-empty-revoked 't=edit(s, "return k.RevokedAt == nil }", "return k.RevokedAt == nil || *k.RevokedAt == \"\" }")'
mutate current-zero-active 't=edit(s, '\''return id, id != "", nil'\'', '\''return id, true, nil'\'')'
mutate follow-redirects 't=edit(s, '\''	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }'\'', '\'''\'')'
mutate provider-pointer-string 't=edit(edit(s, '\''func (Provider) String()'\'', '\''func (*Provider) String()'\''), '\''func (Provider) GoString()'\'', '\''func (*Provider) GoString()'\'')'
mutate orphan-revoke-foreign-id 't=edit(s, '\''	for _, k := range before {\n\t\tif k.KeyID == keyID {\n\t\t\tp.journal("revoke", keyID, "", ErrBadAnswer)\n\t\t\treturn\n\t\t}\n\t}\n'\'', '\'''\'')'
mutate revoke-404-unconfirmed 't=edit(s, '\''case listed(keys, p.meshID(keyID)):'\'', '\''case listed(keys, p.meshID(keyID)) && false:'\'')'
# service.go: rotation of the service account itself and the restart hook.
src=plugins/mesh/service.go
mutate self-abandon-noop 't=edit(s, '\''		_ = sink.Discard(bg, iss.KeyID)\n		_ = p.Revoke(bg, iss.KeyID)'\'', '\''		_ = bg'\'')'
mutate self-abandon-keeps-new-key 't=edit(s, '\''		_ = p.Revoke(bg, iss.KeyID)'\'', '\''		_ = bg'\'')'
mutate self-no-activate-rollback 't=edit(s, '\''	if err := sink.Activate(ctx, iss.KeyID); err != nil {\n		abandon()'\'', '\''	if err := sink.Activate(ctx, iss.KeyID); err != nil {\n		_ = abandon'\'')'
mutate self-revoke-old-before-activate 't=edit(s, '\''	if err := sink.Activate(ctx, iss.KeyID); err != nil {'\'', '\''	_ = p.Revoke(ctx, oldID)\n	if err := sink.Activate(ctx, iss.KeyID); err != nil {'\'')'
mutate self-skip-check 't=edit(s, '\''err != nil || !st.Active {'\'', '\''err != nil || st.Active && false {'\'')'
mutate self-accept-ambiguous 't=edit(s, '\''	if !ok {\n		return RotateResult{}, ErrNoCurrent'\'', '\''	if !ok && false {\n		return RotateResult{}, ErrNoCurrent'\'')'
mutate self-hook-failure-fatal 't=edit(s, '\''			res.HookFailed = true'\'', '\''			return res, ErrHook'\'', 1)'
mutate self-hook-skipped 't=edit(s, '\''	if hook != nil {'\'', '\''	if false {'\'')'
mutate hook-inherit-env 't=edit(edit(s, '\''	cmd.Env = []string{'\'', '\''	cmd.Env = append(os.Environ(), []string{'\''), '\''"KEEP_KEY_ID=" + ev.KeyID,\n	}'\'', '\''"KEEP_KEY_ID=" + ev.KeyID,\n	}...)'\'')'
mutate hook-forward-output 't=edit(s, '\''	if cmd.Run() != nil {\n		return ErrHook'\'', '\''	if o, e := cmd.CombinedOutput(); e != nil {\n		return errors.New(string(o))'\'')'
mutate hook-relative-path 't=edit(s, '\''!filepath.IsAbs(argv[0])'\'', '\''!filepath.IsAbs(argv[0]) && false'\'')'
mutate self-discard-skipped 't=edit(s, "\t\t_ = sink.Discard(bg, iss.KeyID)\n", "")'
mutate self-abandon-uses-caller-ctx 't=edit(s, "context.WithoutCancel(ctx)", "ctx", 1)'
mutate self-stage-lost-uses-caller-ctx 't=edit(s, "\t\tbg, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)\n\t\tdefer cancel()\n\t\t_ = stored", "\t\tbg, cancel := context.WithTimeout(ctx, defaultTimeout)\n\t\tdefer cancel()\n\t\t_ = stored")'
mutate self-old-revoke-error-swallowed 't=edit(s, "	if err := p.Revoke(ctx, res.OldKeyID); err != nil {\n		return res, err\n	}", "	_ = p.Revoke(ctx, res.OldKeyID)")'
mutate self-inactive-wrong-class 't=edit(s, "err = rotation.ErrNotFound", "err = ErrSink")'
src=plugins/mesh/mesh.go
mutate source-empty-token-accepted 't=edit(s, "terr != nil || tok == \"\" {", "terr != nil {")'
mutate source-not-preferred 't=edit(s, "	if p.src != nil {", "	if p.src != nil && p.token == \"\" {")'
src=plugins/mesh/service.go
mutate self-static-token-accepted 't=edit(s, "	if !p.PerCallToken() {", "	if false {", 1)'
mutate revokeold-static-token-accepted 't=edit(edit(edit(s, "	if !p.PerCallToken() {", "	if false {", 2), "	if !p.PerCallToken() {", "	if false {", 1), "if false {", "if !p.PerCallToken() {", 1)'
mutate self-wipe-removed 't=edit(s, "	iss.Value.Wipe()\n", "")'
mutate revokeold-skip-active-check 't=edit(s, "	if !st.Active {\n		return res, ErrNoCurrent", "	if st.Active && false {\n		return res, ErrNoCurrent")'
mutate revokeold-same-key-accepted 't=edit(s, " || res.OldKeyID == res.NewKeyID", "")'
mutate revokeold-bad-id-accepted 't=edit(s, "!rotation.ValidKeyID(res.OldKeyID) || ", "")'
mutate subject-not-account 't=edit(s, "Subject: p.Account(),", "Subject: \"\",")'
mutate hook-path-has-homebrew 't=edit(s, "/usr/sbin:/sbin\"", "/usr/sbin:/sbin:/opt/homebrew/bin\"")'
src=plugins/mesh/mesh.go
mutate source-token-logged 't=edit(s, "	r.Header.Set(\"Authorization\"", "	if p.src != nil {\n		p.log.Info(\"auth\", \"token\", string(tok))\n	}\n	r.Header.Set(\"Authorization\"")'
mutate source-error-forwarded 't=edit(s, "\t\t\treturn nil, rotation.ErrUnavailable\n\t\t}\n\t}\n\tr.Header", "\t\t\treturn nil, terr\n\t\t}\n\t}\n\tr.Header")'
mutate source-cached 't=edit(s, "src: cfg.TokenSource,", "src: cacheOnce(cfg.TokenSource),")+"\nfunc cacheOnce(f TokenSource) TokenSource {\n\tif f == nil {\n\t\treturn nil\n\t}\n\tvar tok Token\n\tdone := false\n\treturn func(ctx context.Context) (Token, error) {\n\t\tif !done {\n\t\t\tt, err := f(ctx)\n\t\t\tif err != nil {\n\t\t\t\treturn \"\", err\n\t\t\t}\n\t\t\ttok, done = t, true\n\t\t}\n\t\treturn tok, nil\n\t}\n}\n"'
# ext.go: the service account as an extension actor (ext_token:self_rotate).
src=plugins/mesh/ext.go
tdir=plugins/mesh tpkg=./...
mutate ext-abandon-sends-delete 't=edit(s, "	if fresh {", "	if fresh && false {")'
mutate ext-prefix-unchecked 't=edit(s, "!strings.HasPrefix(a.Token, extPrefix) || ", "")'
mutate ext-length-unchecked 't=edit(s, "(a.Length != 0 && a.Length != len(a.Token))", "false")'
mutate ext-grace-unchecked 't=edit(s, "cfg.GraceSeconds < 0 || cfg.GraceSeconds > maxGrace ||", "")'
mutate ext-source-optional 't=edit(s, "cfg.TokenSource == nil || ", "")'
mutate ext-redirect-followed 't=edit(s, "	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }", "")'
mutate ext-verify-ignores-new-token 't=edit(s, "	if ok {\n		_, err = e.doWith(ctx, tok,", "	if false {\n		_, err = e.doWith(ctx, tok,")'
mutate ext-verify-denied-counts-active 't=edit(s, "return rotation.Status{Active: false}, nil", "return rotation.Status{Active: true}, nil")'
mutate ext-token-logged 't=edit(s, "	r.Header.Set(\"Accept\", \"application/json\")\n	if ctype", "	e.log.Info(\"auth\", \"token\", string(tok))\n	r.Header.Set(\"Accept\", \"application/json\")\n	if ctype")'
mutate ext-source-error-forwarded 't=edit(s, "		// The source'\''s error text is not forwarded.\n		return nil, rotation.ErrUnavailable", "		return nil, err")'
mutate ext-default-grace-body-sent 't=edit(s, "	if e.grace > 0 {", "	if true {")'
mutate ext-verify-error-swallowed 't=edit(s, "	if err != nil {\n		return rotation.Status{}, err\n	}\n	if ok {", "	if err != nil {\n		return rotation.Status{Active: true}, nil\n	}\n	if ok {")'
mutate ext-abandon-discards-staged 't=edit(s, "func (e *ExtSelf) AbandonKeepsNew() bool { return true }", "func (e *ExtSelf) AbandonKeepsNew() bool { return false }")'
src=plugins/mesh/service.go
mutate orphan-class-dropped 't=edit(s, "		err = errors.Join(ErrOrphaned, err)", "		_ = ErrOrphaned")'
mutate orphan-keepstaged-off 't=edit(s, "		sink = keepStaged{sink}", "		_ = keepStaged{sink}")'
mutate orphan-marks-after-activation 't=edit(s, "	res.activated = true\n", "")'
mutate stage-retry-removed 't=edit(s, "		err = restage(ctx, sink, iss)", "		_ = restage")'
mutate stage-retry-zero-attempts 't=edit(s, "	stageRetries = 3", "	stageRetries = 0")'
mutate provider-abandon-keeps-new 't=edit(s, "func (p *Provider) AbandonKeepsNew() bool { return false }", "func (p *Provider) AbandonKeepsNew() bool { return true }")'
mutate stage-lost-ext-as-agent 't=edit(s, '\''if p.AbandonKeepsNew() {\n\t\t\t// The value is gone'\'', '\''if false {\n\t\t\t// The value is gone'\'')'
mutate stage-lost-ext-revokes 't=edit(s, '\''return res, errors.Join(ErrOrphaned, ErrSink)'\'', '\''_ = p.Revoke(ctx, iss.KeyID)\n\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink)'\'')'
mutate stage-lost-ext-discards 't=edit(s, '\''return res, errors.Join(ErrOrphaned, ErrSink)'\'', '\''_ = stored.Discard(ctx, iss.KeyID)\n\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink)'\'')'
mutate stage-lost-ext-orphan-dropped 't=edit(s, '\''return res, errors.Join(ErrOrphaned, ErrSink)'\'', '\''return res, ErrSink'\'')'
mutate stage-lost-agent-no-revoke 't=edit(s, '\''if rerr := p.Revoke(bg, iss.KeyID); rerr != nil {'\'', '\''if rerr := error(nil); rerr != nil {'\'')'
mutate stage-lost-agent-revoke-error-dropped 't=edit(s, '\''return res, errors.Join(ErrOrphaned, ErrSink, rerr)'\'', '\''return res, ErrSink'\'')'
mutate stage-lost-agent-forwards-sink-error 't=edit(s, '\''\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink, rerr)\n\t\t}\n\t\treturn res, ErrSink'\'', '\''\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink, rerr)\n\t\t}\n\t\treturn res, err'\'')'
mutate stage-lost-ext-forwards-sink-error 't=edit(s, '\''errors.Join(ErrOrphaned, ErrSink)\n'\'', '\''errors.Join(ErrOrphaned, err)\n'\'')'
# Lost answers and held plaintext of the ext_ rotation.
src=plugins/mesh/ext.go
mutate ext-lost-answer-not-orphaned 't=edit(s, "if errors.Is(err, errSent) {", "if false {")'
mutate ext-post-unknown-unmarked 't=edit(s, "if method == http.MethodPost {\n\t\treturn errors.Join(err, errSent)", "if false {\n\t\treturn errors.Join(err, errSent)")'
mutate ext-5xx-post-unmarked 't=edit(s, "if resp.StatusCode >= 500 {", "if false {")'
mutate ext-bad-answer-not-orphaned 't=edit(s, "err = errors.Join(ErrOrphaned, ErrBadAnswer)", "err = ErrBadAnswer")'
mutate ext-forget-keeps-plaintext 't=edit(s, "	delete(e.pending, keyID)\n	e.mu.Unlock()\n}\n\ntype extAnswer", "	e.mu.Unlock()\n}\n\ntype extAnswer")'
src=plugins/mesh/service.go
mutate ext-stage-exhausted-keeps-plaintext 't=edit(s, "f.Forget(iss.KeyID)", "_ = f")'

# pkg/provider/svctoken: Keep's sealed store of the service token, tested in the root module.
src=pkg/provider/svctoken/svctoken.go
tdir=. tpkg=./pkg/provider/svctoken/
mutate svctoken-stage-writes-main 't=edit(s, "s.p.Write(ctx, s.stagedRef(keyID), v)", "s.p.Write(ctx, s.main(), v)")'
mutate svctoken-activate-no-write 't=edit(s, "	if _, err := s.p.Write(ctx, s.main(), v); err != nil {", "	if false {")'
mutate svctoken-discard-mark-not-written 't=edit(edit(s, "s.p.Write(ctx, s.droppedRef(keyID), secret.New([]byte{1}))", "error(nil)"), "if _, err := error(nil); err != nil {", "if err := error(nil); err != nil {")'
mutate svctoken-activate-ignores-mark 't=edit(s, "if mv, _, err := s.p.Resolve(ctx, s.droppedRef(keyID)); err == nil {", "if mv, _, err := s.p.Resolve(ctx, s.droppedRef(keyID)); err == nil && false {")'
mutate svctoken-discard-fails-on-last-version 't=edit(s, "!errors.Is(err, provider.ErrLastVersion) && ", "")'
mutate svctoken-stage-keyid-unchecked 't=edit(s, "	if !rotation.ValidKeyID(keyID) {", "	if false {", 1)'
mutate svctoken-activate-keyid-unchecked 't=edit(s, "	if !rotation.ValidKeyID(keyID) {\n		return ErrKeyID\n	}\n	// A provider cannot", "	// A provider cannot")'
mutate svctoken-discard-keyid-unchecked 't=edit(s, "	if !rotation.ValidKeyID(keyID) {\n		return ErrKeyID\n	}\n	s.mu.Lock()\n	versions", "	s.mu.Lock()\n	versions")'
mutate svctoken-empty-value-staged 't=edit(s, "	if v.IsZero() {", "	if false {", 1)'
mutate svctoken-name-unchecked 't=edit(s, "!namePattern.MatchString(name)", "false")'
mutate svctoken-empty-token-returned 't=edit(s, "	if tok == \"\" {", "	if false {")'
mutate svctoken-activate-keeps-staged 't=edit(s, "	s.dropStaged(ctx, keyID)\n	return nil", "	return nil")'
mutate svctoken-erase-forgets-unknown-versions 't=edit(s, "		if i == maxStagedVersions {", "		if i == 0 {")'
mutate svctoken-bound-taken-for-clean 't=edit(s, "			return ErrStagedLeft", "			return nil")'
mutate svctoken-erase-hits-main 't=edit(s, "	ref := s.stagedRef(keyID)\n	ref.Version = version", "	ref := s.main()\n	ref.Version = version")'
mutate svctoken-leftover-unreported 't=edit(s, "		report(leftClass(err))", "		_ = report")'
mutate svctoken-leftover-raw-error 't=edit(s, "		report(leftClass(err))", "		report(err)")'
mutate svctoken-erase-failure-fails-activate 't=edit(s, "	s.dropStaged(ctx, keyID)\n	return nil", "	s.mu.Lock()\n	vs := s.staged[keyID]\n	s.mu.Unlock()\n	return s.dropVersions(ctx, keyID, vs)")'
mutate svctoken-erase-on-caller-context 't=edit(s, "context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)", "context.WithTimeout(ctx, cleanupTimeout)")'
mutate svctoken-discard-erases 't=edit(s, "	// Persist the discard before", "	s.dropStaged(ctx, keyID)\n	// Persist the discard before")'
# selfrotate.go: the scheduler's rotation of the service token (leak surfaces: log, error, hook argv).
src=plugins/mesh/selfrotate.go
tdir=plugins/mesh tpkg=./...
mutate selfrotate-hook-argv-token 't=edit(s, "		h, err := NewExecHook([]string{cfg.HookPath})", "		tok, _ := cfg.Store.Token(context.Background())\n		h, err := NewExecHook([]string{cfg.HookPath, tok})")'
mutate selfrotate-log-token 't=edit(s, "		log.Info(\"mesh self-rotation\", \"status\", status,", "		tk, _ := cfg.Store.Token(ctx)\n		log.Info(\"mesh self-rotation\", \"token\", tk, \"status\", status,")'
mutate selfrotate-error-carries-token 't=edit(s, "		return err\n	}, nil", "		if err != nil {\n			tk, _ := cfg.Store.Token(ctx)\n			return errors.New(\"rotation failed: \" + tk)\n		}\n		return nil\n	}, nil")'
mutate selfrotate-revoke-retry-removed 't=edit(s, "if err != nil && res.activated {", "if false {")'
mutate selfrotate-hook-skipped 't=edit(s, "	if cfg.HookPath != \"\" {", "	if false {")'
mutate selfrotate-nil-store-accepted 't=edit(s, "	if cfg.Store == nil {", "	if false {")'

# Seed: a restart with the bootstrap file in place must not undo a rotation.
src=pkg/provider/svctoken/svctoken.go
tdir=. tpkg=./pkg/provider/svctoken/
mutate svctoken-seed-replaces-token 't=edit(edit(s, "	cur, _, err := s.p.Resolve(ctx, s.main())\n	if err == nil {", "	cur, _, err := s.p.Resolve(ctx, s.main())\n	if false {", 1), "	if !errors.Is(err, provider.ErrNotFound) {\n		return provider.Meta{}, false, err\n	}\n	m, err", "	if err != nil && !errors.Is(err, provider.ErrNotFound) {\n		return provider.Meta{}, false, err\n	}\n	m, err")'
mutate svctoken-seed-zero-accepted 't=edit(s, "if v.IsZero() {\n		return provider.Meta{}, false, ErrConfig", "if false {\n		return provider.Meta{}, false, ErrConfig")'
mutate svctoken-seed-no-wipe 't=edit(s, "	if err == nil {\n		cur.Wipe()\n		return provider.Meta{}, false, nil", "	if err == nil {\n		_ = cur\n		return provider.Meta{}, false, nil")'
mutate svctoken-has-no-wipe 't=edit(s, "	if err == nil {\n		cur.Wipe()\n		return true, nil", "	if err == nil {\n		_ = cur\n		return true, nil")'

# The bootstrap file and the scheduler of keep-server, and the settings that switch them on.
tdir=. tpkg="./cmd/keep-server/app/ ./internal/config/"
src=cmd/keep-server/app/selfrotate.go
mutate bootstrap-mode-unchecked 't=edit(s, " || fi.Mode().Perm() != 0o600", "")'
mutate bootstrap-follows-symlink 't=edit(s, "|syscall.O_NOFOLLOW", "")'
mutate bootstrap-size-unbounded 't=edit(s, "const maxBootstrapFile = 4096", "const maxBootstrapFile = 1 << 30")'
mutate bootstrap-logs-token 't=edit(s, "	defer v.Wipe()\n	key, err", "	defer v.Wipe()\n	secret.Expose(v, func(b []byte) { logger.Info(\"sealing \" + string(b)) })\n	key, err")'
mutate bootstrap-removes-file 't=edit(s, "	if sealed {\n", "	_ = os.Remove(path)\n	if sealed {\n")'
mutate bootstrap-replaces-sealed-token 't=edit(s, "	if has {\n		return nil", "	if has {\n		_ = store.Stage(ctx, \"00000000-0000-4000-8000-000000000001\", secret.New([]byte(\"x\")))\n		_ = store.Activate(ctx, \"00000000-0000-4000-8000-000000000001\")\n		return nil")'
mutate bootstrap-reads-file-before-sealed-check 't=edit(s, "has, err := store.Has(ctx)", "has, err := false, error(nil)")'
mutate loop-logs-error-text 't=edit(s, "logger.Warn(\"mesh service token rotation failed\", \"error_class\", \"rotation\")", "logger.Warn(\"mesh service token rotation failed\", \"error_class\", err.Error())")'
mutate loop-stops-on-error 't=edit(s, "\"error_class\", \"rotation\")\n", "\"error_class\", \"rotation\")\n				return\n")'
mutate loop-pending-waits-interval 't=edit(s, "wait = min(every, restartCheckEvery)", "wait = every")'
mutate loop-no-retry 't=edit(s, "			if attempt == maxRetries {", "			if true {")'
mutate wire-without-plugin-accepted 't=edit(s, "	if opts.SelfRotate == nil {", "	if false {")'
# Reservation: a caller's provider_ref must not name the sealed service token.
src=pkg/provider/provider.go
tdir=. tpkg="./pkg/provider/ ./cmd/keep-server/app/"
mutate ref-reservation-dropped 't=edit(s, "!strings.HasPrefix(s, reservedRefPrefix)", "!strings.HasPrefix(s, \"\\x00\")")'
mutate ref-reservation-wrong-prefix 't=edit(s, "builtin://mesh-service-token\"", "builtin://mesh-service-tokex\"")'
tdir=. tpkg="./cmd/keep-server/app/ ./internal/config/"
src=internal/config/meshselfrotate.go
mutate config-hook-relative-accepted 't=edit(s, "if g.HookPath != \"\" && !filepath.IsAbs(g.HookPath) {", "if false {")'
mutate config-interval-floor-removed 't=edit(s, "d < time.Second", "d < 0")'
mutate config-extension-not-required 't=edit(s, "	if !extension {", "	if false {", 1)'
mutate config-switch-not-required 't=edit(s, "	if on != \"1\" {", "	if false {")'
mutate config-account-unchecked 't=edit(s, "	if !canonicalUUID(g.AccountID) {", "	if false {")'

# The restart allowlist comes only from KEEP_RESTART_LANES: no built-in list,
# no lanes is no lane, a malformed name stops the start without being echoed.
tdir=. tpkg="./internal/restart/ ./internal/config/ ./cmd/keep-server/app/"
src=internal/restart/restart.go
mutate restart-default-lanes-restored 't=edit(s, "	r := &Repo{db: db,", "	if len(lanes) == 0 {\n		lanes = []string{\"Test\"}\n	}\n	r := &Repo{db: db,")'
mutate restart-allowlist-unchecked 't=edit(s, "	if !r.lanes[lane] {\n		return uuid.Nil, ErrLane", "	if false {\n		return uuid.Nil, ErrLane")'
src=internal/config/config.go
mutate config-restart-lanes-not-read 't=edit(s, "	lanes, err := restartLanes()", "	lanes, err := []string(nil), error(nil)")'
mutate config-restart-lanes-unchecked 't=edit(s, "		if !laneName.MatchString(l) {", "		if false {")'
mutate config-restart-lanes-longer 't=edit(s, "[A-Za-z0-9_-]{0,31}$", "[A-Za-z0-9_-]{0,32}$")'
mutate config-restart-lanes-digit-first 't=edit(s, "^[A-Za-z][A-Za-z0-9_-]", "^[A-Za-z0-9][A-Za-z0-9_-]")'
mutate config-restart-lanes-empty-item-skipped 't=edit(s, "		l := strings.TrimSpace(f)\n", "		l := strings.TrimSpace(f)\n		if l == \"\" {\n			continue\n		}\n")'
mutate config-restart-lanes-error-echoes 't=edit(s, "			return nil, errors.New(\"KEEP_RESTART_LANES must", "			return nil, fmt.Errorf(\"KEEP_RESTART_LANES: %q: must\", l)\n			return nil, errors.New(\"KEEP_RESTART_LANES must")'
src=cmd/keep-server/app/restartqueue.go
mutate restart-queue-config-ignored 't=edit(s, "restart.NewRepo(pool, lanes...)", "restart.NewRepo(pool)")'
mutate restart-queue-silent 't=edit(s, "		logger.Warn(\"restart queue has no lanes", "		_ = logger\n		_ = (\"restart queue has no lanes")'
mutate restart-queue-logs-when-set 't=edit(s, "	if len(lanes) == 0 {", "	if true {")'

# actor.go: the self-rotation account must not be the gate's actor (one actor, one owner of its rotation).
src=plugins/mesh/actor.go
tdir=plugins/mesh tpkg=./...
mutate actor-compare-removed 't=edit(s, "if gate == account {", "if gate == account && false {")'
mutate actor-check-noop 't=edit(s, "	gate, err := x.actorID(ctx)\n	if err != nil {", "	gate, err := uuid.Nil, error(nil)\n	if err != nil {")'
mutate actor-unavailable-fails-start 't=edit(s, "\"error_class\", class(err))\n		return nil", "\"error_class\", class(err))\n		return err")'
mutate actor-unavailable-silent 't=edit(s, "		x.log.Warn(\"mesh self-rotation actor check skipped\", \"error_class\", class(err))\n", "")'
mutate actor-log-token 't=edit(s, "		x.log.Error(\"mesh self-rotation refused\", \"error_class\", \"same_actor\")", "		tk, _ := c.Gate(ctx)\n		x.log.Error(\"mesh self-rotation refused\", \"error_class\", \"same_actor\", \"t\", string(tk))")'
mutate actor-log-body 't=edit(s, "	clear(raw)\n	id, perr", "	e.log.Debug(\"me\", \"body\", string(raw))\n	clear(raw)\n	id, perr")'
src=plugins/mesh/cmd/keep-server/cards.go
mutate actor-sentinel-unmapped 't=edit(s, "		return app.ErrSelfRotateSameActor\n", "		return errors.New(\"refused\")\n")'
mutate actor-vault-source-ignored 't=edit(s, "	src := tokenFromFile(gate.TokenFile)\n	if tokens != nil {\n		src = tokenFromSource(tokens)\n	}\n	err := mesh.CheckSelfRotateActor", "	src := tokenFromFile(gate.TokenFile)\n	_ = tokens\n	err := mesh.CheckSelfRotateActor")'
tdir=. tpkg=./cmd/keep-server/app/
src=cmd/keep-server/app/selfrotate_actor.go
mutate core-actor-check-skipped 't=edit(s, "	if !cfg.MeshExtension || !cfg.MeshGate.Enabled", "	if true || !cfg.MeshExtension || !cfg.MeshGate.Enabled")'
mutate core-actor-missing-check-accepted 't=edit(s, "	if opts.SelfRotateActor == nil {\n		return errors.New", "	if opts.SelfRotateActor == nil {\n		return nil\n	}\n	if false {\n		return errors.New")'
mutate core-actor-forwards-plugin-text 't=edit(s, "		return errors.New(\"mesh service token self-rotation actor check was refused by the Mesh plugin\")", "		return err")'
mutate core-actor-same-not-refused 't=edit(s, "		return ErrSelfRotateSameActor\n", "		return nil\n")'

mutation_shard_finish
exit $fail
