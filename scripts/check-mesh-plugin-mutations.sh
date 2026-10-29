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

# The unmutated module must be green, or every red below proves nothing.
mutation_apply_only || (cd "$root/plugins/mesh" && go test -timeout 120s -count=1 ./... >"$work/base" 2>&1) || { echo "FAIL baseline is red"; exit 1; }

mutate log-response-body 't=s.replace('\''	var a issueAnswer'\'', '\''	p.log.Debug("resp", "body", string(body))\n	var a issueAnswer'\'',1)'
mutate forward-error-body 't=s.replace('\''	clear(body)\n	switch resp.StatusCode {'\'', '\''	return nil, errors.New(string(body))\n	switch resp.StatusCode {'\'',1)'
mutate no-keyid-validation 't=s.replace('\''if !rotation.ValidKeyID(keyID) {'\'', '\''if false {'\'')'
mutate dualkey-false 't=s.replace('\''DualKey: true'\'', '\''DualKey: false'\'')'
mutate current-multi-active 't=s.replace('\''			return "", false, nil\n		}\n		id = k.KeyID'\'', '\''		}\n		id = k.KeyID'\'',1)'
mutate accept-empty-value 't=s.replace('\''|| a.Key == ""'\'', '\'''\'')'
mutate token-string 't=s.replace('\''func (Token) String() string { return secret.Redacted }'\'', '\''func (t Token) String() string { return string(t) }'\'').replace('\''func (Token) GoString() string { return secret.Redacted }'\'', '\''func (t Token) GoString() string { return string(t) }'\'')'
mutate token-marshal 't=s.replace('\''return []byte(secret.Redacted), nil'\'', '\''return []byte(string(t)), nil'\'').replace('\''func (Token) MarshalText'\'', '\''func (t Token) MarshalText'\'')'
mutate provider-string 't=s.replace('\''func (Provider) String() string   { return "mesh.Provider" }'\'', '\'''\'').replace('\''func (Provider) GoString() string { return "mesh.Provider" }'\'', '\'''\'')'
mutate plain-http-off-loopback 't=s.replace('\''(u.Scheme != "http" || !loopback(u.Hostname()))'\'', '\''false'\'')'
mutate orphan-key-kept 't=s.replace('\''			p.revokeOrphan(ctx, a.KeyID, before)'\'', '\''			_ = before'\'')'
mutate log-token 't=s.replace('\''	resp, err := p.hc.Do(r)\n'\'', '\''	p.log.Info("auth", "token", string(p.token))\n	resp, err := p.hc.Do(r)\n'\'',1)'
mutate log-transport-error 't=s.replace('\''	resp, err := p.hc.Do(r)\n	if err != nil {\n'\'', '\''	resp, err := p.hc.Do(r)\n	if err != nil {\n		p.log.Warn(err.Error())\n'\'',1)'
mutate log-list-body 't=s.replace('\''	var a struct {\n		Keys'\'', '\''	p.log.Debug("list", "body", string(body))\n	var a struct {\n		Keys'\'',1)'
mutate issue-accept-bad-keyid 't=s.replace('\''derr != nil || !rotation.ValidKeyID(a.KeyID) ||'\'', '\''derr != nil ||'\'',1)'
mutate list-accept-bad-keyid 't=s.replace("if !rotation.ValidKeyID(k.KeyID) {", "if !rotation.ValidKeyID(k.KeyID) && k.KeyID == \"\" {")'
mutate current-zero-active 't=s.replace('\''return id, id != "", nil'\'', '\''return id, true, nil'\'',1)'
mutate follow-redirects 't=s.replace('\''	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }'\'', '\'''\'',1)'
mutate provider-pointer-string 't=s.replace('\''func (Provider) String()'\'', '\''func (*Provider) String()'\'').replace('\''func (Provider) GoString()'\'', '\''func (*Provider) GoString()'\'')'
mutate orphan-revoke-foreign-id 't=s.replace('\''	for _, k := range before {\n\t\tif k.KeyID == keyID {\n\t\t\tp.journal("revoke", keyID, "", ErrBadAnswer)\n\t\t\treturn\n\t\t}\n\t}\n'\'', '\'''\'',1)'
mutate revoke-404-unconfirmed 't=s.replace('\''case listed(keys, keyID):'\'', '\''case listed(keys, keyID) && false:'\'',1)'
# service.go: rotation of the service account itself and the restart hook.
src=plugins/mesh/service.go
mutate self-abandon-noop 't=s.replace('\''		_ = sink.Discard(bg, iss.KeyID)\n		_ = p.Revoke(bg, iss.KeyID)'\'', '\''		_ = bg'\'',1)'
mutate self-abandon-keeps-new-key 't=s.replace('\''		_ = p.Revoke(bg, iss.KeyID)'\'', '\''		_ = bg'\'',1)'
mutate self-no-activate-rollback 't=s.replace('\''	if err := sink.Activate(ctx, iss.KeyID); err != nil {\n		abandon()'\'', '\''	if err := sink.Activate(ctx, iss.KeyID); err != nil {\n		_ = abandon'\'',1)'
mutate self-revoke-old-before-activate 't=s.replace('\''	if err := sink.Activate(ctx, iss.KeyID); err != nil {'\'', '\''	_ = p.Revoke(ctx, oldID)\n	if err := sink.Activate(ctx, iss.KeyID); err != nil {'\'',1)'
mutate self-skip-check 't=s.replace('\''err != nil || !st.Active {'\'', '\''err != nil || st.Active && false {'\'',1)'
mutate self-accept-ambiguous 't=s.replace('\''	if !ok {\n		return RotateResult{}, ErrNoCurrent'\'', '\''	if !ok && false {\n		return RotateResult{}, ErrNoCurrent'\'',1)'
mutate self-hook-failure-fatal 't=s.replace('\''			res.HookFailed = true'\'', '\''			return res, ErrHook'\'',1)'
mutate self-hook-skipped 't=s.replace('\''	if hook != nil {'\'', '\''	if false {'\'',1)'
mutate hook-inherit-env 't=s.replace('\''	cmd.Env = []string{'\'', '\''	cmd.Env = append(os.Environ(), []string{'\'',1).replace('\''"KEEP_KEY_ID=" + ev.KeyID,\n	}'\'', '\''"KEEP_KEY_ID=" + ev.KeyID,\n	}...)'\'',1)'
mutate hook-forward-output 't=s.replace('\''	if cmd.Run() != nil {\n		return ErrHook'\'', '\''	if o, e := cmd.CombinedOutput(); e != nil {\n		return errors.New(string(o))'\'',1)'
mutate hook-relative-path 't=s.replace('\''!filepath.IsAbs(argv[0])'\'', '\''!filepath.IsAbs(argv[0]) && false'\'',1)'
mutate self-discard-skipped 't=s.replace("\t\t_ = sink.Discard(bg, iss.KeyID)\n", "",1)'
mutate self-abandon-uses-caller-ctx 't=s.replace("context.WithoutCancel(ctx)", "ctx",1)'
mutate self-stage-lost-uses-caller-ctx 't=s.replace("\t\tbg, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)\n\t\tdefer cancel()\n\t\t_ = stored", "\t\tbg, cancel := context.WithTimeout(ctx, defaultTimeout)\n\t\tdefer cancel()\n\t\t_ = stored",1)'
mutate self-old-revoke-error-swallowed 't=s.replace("	if err := p.Revoke(ctx, res.OldKeyID); err != nil {\n		return res, err\n	}", "	_ = p.Revoke(ctx, res.OldKeyID)",1)'
mutate self-inactive-wrong-class 't=s.replace("err = rotation.ErrNotFound", "err = ErrSink",1)'
src=plugins/mesh/mesh.go
mutate source-empty-token-accepted 't=s.replace("terr != nil || tok == \"\" {", "terr != nil {",1)'
mutate source-not-preferred 't=s.replace("	if p.src != nil {", "	if p.src != nil && p.token == \"\" {",1)'
src=plugins/mesh/service.go
mutate self-static-token-accepted 't=s.replace("	if !p.PerCallToken() {", "	if false {",1)'
mutate revokeold-static-token-accepted 't=s.replace("	if !p.PerCallToken() {", "	if false {").replace("if false {", "if !p.PerCallToken() {",1)'
mutate self-wipe-removed 't=s.replace("	iss.Value.Wipe()\n", "",1)'
mutate revokeold-skip-active-check 't=s.replace("	if !st.Active {\n		return res, ErrNoCurrent", "	if st.Active && false {\n		return res, ErrNoCurrent",1)'
mutate revokeold-same-key-accepted 't=s.replace(" || res.OldKeyID == res.NewKeyID", "",1)'
mutate revokeold-bad-id-accepted 't=s.replace("!rotation.ValidKeyID(res.OldKeyID) || ", "",1)'
mutate subject-not-account 't=s.replace("Subject: p.Account(),", "Subject: \"\",",1)'
mutate hook-path-has-homebrew 't=s.replace("/usr/sbin:/sbin\"", "/usr/sbin:/sbin:/opt/homebrew/bin\"",1)'
src=plugins/mesh/mesh.go
mutate source-token-logged 't=s.replace("	r.Header.Set(\"Authorization\"", "	if p.src != nil {\n		p.log.Info(\"auth\", \"token\", string(tok))\n	}\n	r.Header.Set(\"Authorization\"",1)'
mutate source-error-forwarded 't=s.replace("\t\t\treturn nil, rotation.ErrUnavailable\n\t\t}\n\t}\n\tr.Header", "\t\t\treturn nil, terr\n\t\t}\n\t}\n\tr.Header",1)'
mutate source-cached 't=s.replace("src: cfg.TokenSource,", "src: cacheOnce(cfg.TokenSource),",1)+"\nfunc cacheOnce(f TokenSource) TokenSource {\n\tif f == nil {\n\t\treturn nil\n\t}\n\tvar tok Token\n\tdone := false\n\treturn func(ctx context.Context) (Token, error) {\n\t\tif !done {\n\t\t\tt, err := f(ctx)\n\t\t\tif err != nil {\n\t\t\t\treturn \"\", err\n\t\t\t}\n\t\t\ttok, done = t, true\n\t\t}\n\t\treturn tok, nil\n\t}\n}\n"'
# ext.go: the service account as an extension actor (ext_token:self_rotate).
src=plugins/mesh/ext.go
tdir=plugins/mesh tpkg=./...
mutate ext-abandon-sends-delete 't=s.replace("	if fresh {", "	if fresh && false {",1)'
mutate ext-prefix-unchecked 't=s.replace("!strings.HasPrefix(a.Token, extPrefix) || ", "",1)'
mutate ext-length-unchecked 't=s.replace("(a.Length != 0 && a.Length != len(a.Token))", "false",1)'
mutate ext-grace-unchecked 't=s.replace("cfg.GraceSeconds < 0 || cfg.GraceSeconds > maxGrace ||", "",1)'
mutate ext-source-optional 't=s.replace("cfg.TokenSource == nil || ", "",1)'
mutate ext-redirect-followed 't=s.replace("	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }", "",1)'
mutate ext-verify-ignores-new-token 't=s.replace("	if ok {\n		_, err = e.doWith(ctx, tok,", "	if false {\n		_, err = e.doWith(ctx, tok,",1)'
mutate ext-verify-denied-counts-active 't=s.replace("return rotation.Status{Active: false}, nil", "return rotation.Status{Active: true}, nil",1)'
mutate ext-token-logged 't=s.replace("	r.Header.Set(\"Accept\", \"application/json\")\n	if ctype", "	e.log.Info(\"auth\", \"token\", string(tok))\n	r.Header.Set(\"Accept\", \"application/json\")\n	if ctype",1)'
mutate ext-source-error-forwarded 't=s.replace("		// The source'\''s error text is not forwarded.\n		return nil, rotation.ErrUnavailable", "		return nil, err",1)'
mutate ext-default-grace-body-sent 't=s.replace("	if e.grace > 0 {", "	if true {",1)'
mutate ext-verify-error-swallowed 't=s.replace("	if err != nil {\n		return rotation.Status{}, err\n	}\n	if ok {", "	if err != nil {\n		return rotation.Status{Active: true}, nil\n	}\n	if ok {",1)'
mutate ext-abandon-discards-staged 't=s.replace("func (e *ExtSelf) AbandonKeepsNew() bool { return true }", "func (e *ExtSelf) AbandonKeepsNew() bool { return false }",1)'
src=plugins/mesh/service.go
mutate orphan-class-dropped 't=s.replace("		err = errors.Join(ErrOrphaned, err)", "		_ = ErrOrphaned",1)'
mutate orphan-keepstaged-off 't=s.replace("		sink = keepStaged{sink}", "		_ = keepStaged{sink}",1)'
mutate orphan-marks-after-activation 't=s.replace("	res.activated = true\n", "",1)'
mutate stage-retry-removed 't=s.replace("		err = restage(ctx, sink, iss)", "		_ = restage",1)'
mutate stage-retry-zero-attempts 't=s.replace("	stageRetries = 3", "	stageRetries = 0",1)'
mutate provider-abandon-keeps-new 't=s.replace("func (p *Provider) AbandonKeepsNew() bool { return false }", "func (p *Provider) AbandonKeepsNew() bool { return true }",1)'
mutate stage-lost-ext-as-agent 't=s.replace('\''if p.AbandonKeepsNew() {\n\t\t\t// The value is gone'\'', '\''if false {\n\t\t\t// The value is gone'\'',1)'
mutate stage-lost-ext-revokes 't=s.replace('\''return res, errors.Join(ErrOrphaned, ErrSink)'\'', '\''_ = p.Revoke(ctx, iss.KeyID)\n\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink)'\'',1)'
mutate stage-lost-ext-discards 't=s.replace('\''return res, errors.Join(ErrOrphaned, ErrSink)'\'', '\''_ = stored.Discard(ctx, iss.KeyID)\n\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink)'\'',1)'
mutate stage-lost-ext-orphan-dropped 't=s.replace('\''return res, errors.Join(ErrOrphaned, ErrSink)'\'', '\''return res, ErrSink'\'',1)'
mutate stage-lost-agent-no-revoke 't=s.replace('\''if rerr := p.Revoke(bg, iss.KeyID); rerr != nil {'\'', '\''if rerr := error(nil); rerr != nil {'\'',1)'
mutate stage-lost-agent-revoke-error-dropped 't=s.replace('\''return res, errors.Join(ErrOrphaned, ErrSink, rerr)'\'', '\''return res, ErrSink'\'',1)'
mutate stage-lost-agent-forwards-sink-error 't=s.replace('\''\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink, rerr)\n\t\t}\n\t\treturn res, ErrSink'\'', '\''\t\t\treturn res, errors.Join(ErrOrphaned, ErrSink, rerr)\n\t\t}\n\t\treturn res, err'\'',1)'
mutate stage-lost-ext-forwards-sink-error 't=s.replace('\''errors.Join(ErrOrphaned, ErrSink)\n'\'', '\''errors.Join(ErrOrphaned, err)\n'\'',1)'
# Lost answers and held plaintext of the ext_ rotation.
src=plugins/mesh/ext.go
mutate ext-lost-answer-not-orphaned 't=s.replace("if errors.Is(err, errSent) {", "if false {",1)'
mutate ext-post-unknown-unmarked 't=s.replace("if method == http.MethodPost {\n\t\treturn errors.Join(err, errSent)", "if false {\n\t\treturn errors.Join(err, errSent)",1)'
mutate ext-5xx-post-unmarked 't=s.replace("if resp.StatusCode >= 500 {", "if false {",1)'
mutate ext-bad-answer-not-orphaned 't=s.replace("err = errors.Join(ErrOrphaned, ErrBadAnswer)", "err = ErrBadAnswer",1)'
mutate ext-forget-keeps-plaintext 't=s.replace("	delete(e.pending, keyID)\n	e.mu.Unlock()\n}\n\ntype extAnswer", "	e.mu.Unlock()\n}\n\ntype extAnswer",1)'
src=plugins/mesh/service.go
mutate ext-stage-exhausted-keeps-plaintext 't=s.replace("f.Forget(iss.KeyID)", "_ = f",1)'

# pkg/provider/svctoken: Keep's sealed store of the service token, tested in the root module.
src=pkg/provider/svctoken/svctoken.go
tdir=. tpkg=./pkg/provider/svctoken/
mutate svctoken-stage-writes-main 't=s.replace("s.p.Write(ctx, s.stagedRef(keyID), v)", "s.p.Write(ctx, s.main(), v)",1)'
mutate svctoken-activate-no-write 't=s.replace("	if _, err := s.p.Write(ctx, s.main(), v); err != nil {", "	if false {",1)'
mutate svctoken-discard-mark-not-written 't=s.replace("s.p.Write(ctx, s.droppedRef(keyID), secret.New([]byte{1}))", "error(nil)",1).replace("if _, err := error(nil); err != nil {", "if err := error(nil); err != nil {",1)'
mutate svctoken-activate-ignores-mark 't=s.replace("if mv, _, err := s.p.Resolve(ctx, s.droppedRef(keyID)); err == nil {", "if mv, _, err := s.p.Resolve(ctx, s.droppedRef(keyID)); err == nil && false {",1)'
mutate svctoken-discard-fails-on-last-version 't=s.replace("!errors.Is(err, provider.ErrLastVersion) && ", "",1)'
mutate svctoken-stage-keyid-unchecked 't=s.replace("	if !rotation.ValidKeyID(keyID) {", "	if false {",1)'
mutate svctoken-activate-keyid-unchecked 't=s.replace("	if !rotation.ValidKeyID(keyID) {\n		return ErrKeyID\n	}\n	// A provider cannot", "	// A provider cannot",1)'
mutate svctoken-discard-keyid-unchecked 't=s.replace("	if !rotation.ValidKeyID(keyID) {\n		return ErrKeyID\n	}\n	s.mu.Lock()\n	versions", "	s.mu.Lock()\n	versions",1)'
mutate svctoken-empty-value-staged 't=s.replace("	if v.IsZero() {", "	if false {",1)'
mutate svctoken-name-unchecked 't=s.replace("!namePattern.MatchString(name)", "false",1)'
mutate svctoken-empty-token-returned 't=s.replace("	if tok == \"\" {", "	if false {",1)'
mutate svctoken-activate-keeps-staged 't=s.replace("	s.dropStaged(ctx, keyID)\n	return nil", "	return nil",1)'
mutate svctoken-erase-forgets-unknown-versions 't=s.replace("		if i == maxStagedVersions {", "		if i == 0 {",1)'
mutate svctoken-bound-taken-for-clean 't=s.replace("			return ErrStagedLeft", "			return nil",1)'
mutate svctoken-erase-hits-main 't=s.replace("	ref := s.stagedRef(keyID)\n	ref.Version = version", "	ref := s.main()\n	ref.Version = version",1)'
mutate svctoken-leftover-unreported 't=s.replace("		report(leftClass(err))", "		_ = report",1)'
mutate svctoken-leftover-raw-error 't=s.replace("		report(leftClass(err))", "		report(err)",1)'
mutate svctoken-erase-failure-fails-activate 't=s.replace("	s.dropStaged(ctx, keyID)\n	return nil", "	s.mu.Lock()\n	vs := s.staged[keyID]\n	s.mu.Unlock()\n	return s.dropVersions(ctx, keyID, vs)",1)'
mutate svctoken-erase-on-caller-context 't=s.replace("context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)", "context.WithTimeout(ctx, cleanupTimeout)",1)'
mutate svctoken-discard-erases 't=s.replace("	// Persist the discard before", "	s.dropStaged(ctx, keyID)\n	// Persist the discard before",1)'
# selfrotate.go: the scheduler's rotation of the service token (leak surfaces: log, error, hook argv).
src=plugins/mesh/selfrotate.go
tdir=plugins/mesh tpkg=./...
mutate selfrotate-hook-argv-token 't=s.replace("		h, err := NewExecHook([]string{cfg.HookPath})", "		tok, _ := cfg.Store.Token(context.Background())\n		h, err := NewExecHook([]string{cfg.HookPath, tok})",1)'
mutate selfrotate-log-token 't=s.replace("		log.Info(\"mesh self-rotation\", \"status\", status,", "		tk, _ := cfg.Store.Token(ctx)\n		log.Info(\"mesh self-rotation\", \"token\", tk, \"status\", status,",1)'
mutate selfrotate-error-carries-token 't=s.replace("		return err\n	}, nil", "		if err != nil {\n			tk, _ := cfg.Store.Token(ctx)\n			return errors.New(\"rotation failed: \" + tk)\n		}\n		return nil\n	}, nil",1)'
mutate selfrotate-revoke-retry-removed 't=s.replace("if err != nil && res.activated {", "if false {",1)'
mutate selfrotate-hook-skipped 't=s.replace("	if cfg.HookPath != \"\" {", "	if false {",1)'
mutate selfrotate-nil-store-accepted 't=s.replace("	if cfg.Store == nil {", "	if false {",1)'

# Seed: a restart with the bootstrap file in place must not undo a rotation.
src=pkg/provider/svctoken/svctoken.go
tdir=. tpkg=./pkg/provider/svctoken/
mutate svctoken-seed-replaces-token 't=s.replace("	cur, _, err := s.p.Resolve(ctx, s.main())\n	if err == nil {", "	cur, _, err := s.p.Resolve(ctx, s.main())\n	if false {",1).replace("	if !errors.Is(err, provider.ErrNotFound) {\n		return provider.Meta{}, false, err\n	}\n	m, err", "	if err != nil && !errors.Is(err, provider.ErrNotFound) {\n		return provider.Meta{}, false, err\n	}\n	m, err",1)'
mutate svctoken-seed-zero-accepted 't=s.replace("if v.IsZero() {\n		return provider.Meta{}, false, ErrConfig", "if false {\n		return provider.Meta{}, false, ErrConfig",1)'
mutate svctoken-seed-no-wipe 't=s.replace("	if err == nil {\n		cur.Wipe()\n		return provider.Meta{}, false, nil", "	if err == nil {\n		_ = cur\n		return provider.Meta{}, false, nil",1)'
mutate svctoken-has-no-wipe 't=s.replace("	if err == nil {\n		cur.Wipe()\n		return true, nil", "	if err == nil {\n		_ = cur\n		return true, nil",1)'

# The bootstrap file and the scheduler of keep-server, and the settings that switch them on.
tdir=. tpkg="./cmd/keep-server/app/ ./internal/config/"
src=cmd/keep-server/app/selfrotate.go
mutate bootstrap-mode-unchecked 't=s.replace(" || fi.Mode().Perm() != 0o600", "",1)'
mutate bootstrap-follows-symlink 't=s.replace("|syscall.O_NOFOLLOW", "",1)'
mutate bootstrap-size-unbounded 't=s.replace("const maxBootstrapFile = 4096", "const maxBootstrapFile = 1 << 30",1)'
mutate bootstrap-logs-token 't=s.replace("	defer v.Wipe()\n	key, err", "	defer v.Wipe()\n	secret.Expose(v, func(b []byte) { logger.Info(\"sealing \" + string(b)) })\n	key, err",1)'
mutate bootstrap-removes-file 't=s.replace("	if sealed {\n", "	_ = os.Remove(path)\n	if sealed {\n",1)'
mutate bootstrap-replaces-sealed-token 't=s.replace("	if has {\n		return nil", "	if has {\n		_ = store.Stage(ctx, \"00000000-0000-4000-8000-000000000001\", secret.New([]byte(\"x\")))\n		_ = store.Activate(ctx, \"00000000-0000-4000-8000-000000000001\")\n		return nil",1)'
mutate bootstrap-reads-file-before-sealed-check 't=s.replace("has, err := store.Has(ctx)", "has, err := false, error(nil)",1)'
mutate loop-logs-error-text 't=s.replace("logger.Warn(\"mesh service token rotation failed\", \"error_class\", \"rotation\")", "logger.Warn(\"mesh service token rotation failed\", \"error_class\", err.Error())",1)'
mutate loop-stops-on-error 't=s.replace("\"error_class\", \"rotation\")\n", "\"error_class\", \"rotation\")\n				return\n",1)'
mutate loop-pending-waits-interval 't=s.replace("wait = min(every, restartCheckEvery)", "wait = every",1)'
mutate loop-no-retry 't=s.replace("			if attempt == maxRetries {", "			if true {",1)'
mutate wire-without-plugin-accepted 't=s.replace("	if opts.SelfRotate == nil {", "	if false {",1)'
# Reservation: a caller's provider_ref must not name the sealed service token.
src=pkg/provider/provider.go
tdir=. tpkg="./pkg/provider/ ./cmd/keep-server/app/"
mutate ref-reservation-dropped 't=s.replace("!strings.HasPrefix(s, reservedRefPrefix)", "!strings.HasPrefix(s, \"\\x00\")",1)'
mutate ref-reservation-wrong-prefix 't=s.replace("builtin://mesh-service-token\"", "builtin://mesh-service-tokex\"",1)'
tdir=. tpkg="./cmd/keep-server/app/ ./internal/config/"
src=internal/config/meshselfrotate.go
mutate config-hook-relative-accepted 't=s.replace("if g.HookPath != \"\" && !filepath.IsAbs(g.HookPath) {", "if false {",1)'
mutate config-interval-floor-removed 't=s.replace("d < time.Second", "d < 0",1)'
mutate config-extension-not-required 't=s.replace("	if !extension {", "	if false {",1)'
mutate config-switch-not-required 't=s.replace("	if on != \"1\" {", "	if false {",1)'
mutate config-account-unchecked 't=s.replace("	if !canonicalUUID(g.AccountID) {", "	if false {",1)'

# actor.go: the self-rotation account must not be the gate's actor (one actor, one owner of its rotation).
src=plugins/mesh/actor.go
tdir=plugins/mesh tpkg=./...
mutate actor-compare-removed 't=s.replace("if gate == account {", "if gate == account && false {",1)'
mutate actor-check-noop 't=s.replace("	gate, err := x.actorID(ctx)\n	if err != nil {", "	gate, err := uuid.Nil, error(nil)\n	if err != nil {",1)'
mutate actor-unavailable-fails-start 't=s.replace("\"error_class\", class(err))\n		return nil", "\"error_class\", class(err))\n		return err",1)'
mutate actor-unavailable-silent 't=s.replace("		x.log.Warn(\"mesh self-rotation actor check skipped\", \"error_class\", class(err))\n", "",1)'
mutate actor-log-token 't=s.replace("		x.log.Error(\"mesh self-rotation refused\", \"error_class\", \"same_actor\")", "		tk, _ := c.Gate(ctx)\n		x.log.Error(\"mesh self-rotation refused\", \"error_class\", \"same_actor\", \"t\", string(tk))",1)'
mutate actor-log-body 't=s.replace("	clear(raw)\n	id, perr", "	e.log.Debug(\"me\", \"body\", string(raw))\n	clear(raw)\n	id, perr",1)'
src=plugins/mesh/cmd/keep-server/cards.go
mutate actor-sentinel-unmapped 't=s.replace("		return app.ErrSelfRotateSameActor\n", "		return errors.New(\"refused\")\n",1)'
mutate actor-vault-source-ignored 't=s.replace("	src := tokenFromFile(gate.TokenFile)\n	if tokens != nil {\n		src = tokenFromSource(tokens)\n	}\n	err := mesh.CheckSelfRotateActor", "	src := tokenFromFile(gate.TokenFile)\n	_ = tokens\n	err := mesh.CheckSelfRotateActor",1)'
tdir=. tpkg=./cmd/keep-server/app/
src=cmd/keep-server/app/selfrotate_actor.go
mutate core-actor-check-skipped 't=s.replace("	if !cfg.MeshExtension || !cfg.MeshGate.Enabled", "	if true || !cfg.MeshExtension || !cfg.MeshGate.Enabled",1)'
mutate core-actor-missing-check-accepted 't=s.replace("	if opts.SelfRotateActor == nil {\n		return errors.New", "	if opts.SelfRotateActor == nil {\n		return nil\n	}\n	if false {\n		return errors.New",1)'
mutate core-actor-forwards-plugin-text 't=s.replace("		return errors.New(\"mesh service token self-rotation actor check was refused by the Mesh plugin\")", "		return err",1)'
mutate core-actor-same-not-refused 't=s.replace("		return ErrSelfRotateSameActor\n", "		return nil\n",1)'

mutation_shard_finish
exit $fail
