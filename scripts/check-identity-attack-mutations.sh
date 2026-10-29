#!/bin/sh
# Proves the identity attacks in test/security can fail: in a scratch copy of
# the tree, switch off one protection of internal/identity at a time and
# require `go test -run ^TestIdentity_ ./test/security/` to go red — on the
# attack (or subtest) named for it, and for the right reason.
# KEEP_DATABASE_URL must point at an already-migrated database
# (`go run ./cmd/keep-server migrate up`).
#
# A mutant counts only when ALL of these hold:
#   - the run fails (an attack went red);
#   - the output has `--- FAIL: WANT` where WANT is the top-level test, or
#     test/subtest, this mutation is meant to trip (a prefix match);
#   - if a NEEDLE is given, the output also contains it (the assertion text
#     or surface label the mutation must trip — for attacks without subtests);
#   - the output carries no token-shaped string or base64 blob (a failing
#     check must not print the credential it found);
#   - the red is not a build failure and not a SQL syntax/schema error
#     (SQLSTATE class 42) — a mutant that breaks the code instead of removing
#     the protection proves nothing. The one exception is a mutant of an
#     attack's own statement (SQLERR_OK=1): it turns a refusal into a typo,
#     and the attack must not take the typo for the database's refusal.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
mutation_shard_init

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change
# (seen as "could not import internal/chacha8rand ... no such file").
# Scoping the cache to each run removes the sharing, not just the
# symptom. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=internal/identity

if [ -z "${KEEP_DATABASE_URL:-}" ] && ! mutation_apply_only; then
	echo "FAIL check-identity-attack-mutations: KEEP_DATABASE_URL is not set — the attacks would SKIP, not fail"
	exit 1
fi

fail=0
name="" want="" needle="" broken=0 expect=clean
# A token's random part is 52 characters of [a-z2-7]; its base64 (any offset, any
# header around it) is a run of 72 or more base64 characters. Matched
# case-insensitively (see the `grep -i` in run): ParseKind lower-cases a
# token's body on generation, but a mutant that never went through that path
# (say, one that upper-cases before printing) must not get a pass just
# because the letters no longer match [a-z2-7] literally.
# NOT widened to base64url's `-`/`_`: a go test subtest name IS underscores
# and hyphens joining ordinary words (spaces become `_`; "cross-org" keeps
# its `-`), so adding either to this class turns long, wholly unremarkable
# subtest names into 72-character "leaks" — every mutant tripped this at
# once (25.09) the one time it was tried. Base64url tokens would need a
# narrower rule (with `+`/`/` excluded, so it cannot also fire on the
# standard alphabet's own class) if this package ever emits one.
# It is also not a gap for THIS package's own tokens: their plaintext is
# `keep_` + one of `a`/`s`/`u` + `_` + [a-z2-7]{52} — every byte from an
# alphabet with no `-`/`_`/`~` in it. A base64/base64url 6-bit group only
# takes value 62 or 63 (the two alphabets' only difference) when specific
# high bits of three consecutive source bytes line up a particular way;
# checked by brute force over this exact source alphabet at every one of
# the 3 byte-offsets a token can start at, none ever does. So a token's
# base64url encoding is byte-for-byte identical to its standard base64 and
# is already caught by the `[A-Za-z0-9+/]{72,}` alternative above.
#
# The third alternative, `[0-9a-f]{64}`, is for raw entropy printed as hex
# before it is base32-encoded into a token (32 bytes = 64 hex digits) — a
# token's OWN 52-character base32 body does not collide with it (base32
# uses `[a-z2-7]`, not `[0-9a-f]`, and is a different length), but the
# bytes behind it would if a mutant prints them straight with `%x`. Checked
# against the baseline (unmodified tree) run below: nothing else this
# package's tests print is 64 hex characters long, so this alternative sees
# no false positive here. If this package ever legitimately prints a
# 64-character hex string (a SHA-256 digest, say) that check will need a
# narrower rule — this comment is that limitation, recorded up front.
LEAK_RE='[a-z2-7]{52}|[A-Za-z0-9+/]{72,}|[0-9a-f]{64}'

# mask - blot out anything LEAK_RE-shaped in a line meant only to help a
# maintainer see WHY a mutant did not match (build failure, wrong test,
# missing needle) — printed straight from `go test -v` output, before this
# script's own leak check further down ever runs on it. The classes mirror
# LEAK_RE with the case spelled out explicitly instead of relying on a
# case-insensitive sed flag: portable across the sed this script actually
# runs under (BSD locally, busybox in the golang:1.25-alpine CI image).
mask() {
	sed -E 's/[A-Za-z2-7]{52,}|[A-Za-z0-9+\/]{72,}|[0-9a-fA-F]{64}/<token-shaped>/g'
}

# begin NAME WANT [NEEDLE] — start a mutant: a fresh copy of the tree.
begin() {
	name=$1 want=$2 needle=${3:-} broken=0
	if ! mutation_selected; then broken=1; return; fi
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
}

# edit FILE FROM TO — replace the first literal FROM with TO in
# internal/identity/FILE of the copy (or in FILE itself when it is given as an
# internal/... or test/... path). May be repeated for one mutant.
edit() {
	[ "$broken" = 1 ] && return
	case $1 in
	internal/* | test/*) src=$1 ;;
	*) src=$pkg/$1 ;;
	esac
	# ENVIRON, not `awk -v`: -v interprets backslash escapes (\n would become a newline).
	if ! FROM=$2 TO=$3 awk '
		BEGIN { from = ENVIRON["FROM"]; to = ENVIRON["TO"] }
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$work/tree/$src" >"$work/edited"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		broken=1
		return
	fi
	cp "$work/edited" "$work/tree/$src"
}

# run [EXPECT] — run the attacks on the copy and judge the result. EXPECT
# defaults to "clean": the usual case, where the mutant must go red on $want
# with none of its own failure text carrying a token-shaped string. Pass
# "leak" for a mutant built to prove the opposite — that LEAK_RE and the
# indented-lines filter actually catch a leak when one is there — where the
# leak branch below is this run's success, not its failure, and NOT finding
# a leak is what fails it.
run() {
	[ "$broken" = 1 ] && return
	expect=${1:-clean}
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 600s -count=1 -v -run "^${want%%/*}\$" ./test/security/ >"$work/out" 2>&1); then
		echo "FAIL $name: attacks stayed green with the protection switched off"
		fail=1
	else
		test_status=$?
		judge_run
	fi
}

judge_run() {
	if [ "$test_status" -ne 1 ] ||
		! awk '$1 == "FAIL" && $2 == "github.com/entire-vc/evc-keep/test/security" && $3 ~ /^[0-9.]+s$/ { found=1 } END { exit !found }' "$work/out" ||
		grep -q -E '^panic:|^fatal error:|signal: killed|--- SKIP' "$work/out"; then
		echo "FAIL $name: invalid test run (incomplete process, timeout, or skip; exit $test_status)"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif grep -q -e '\[build failed\]' -e '\[setup failed\]' "$work/out"; then
		echo "FAIL $name: red only because the mutant does not build:"
		grep -e 'build failed' -e '\.go:[0-9]*:[0-9]*:' "$work/out" | head -3 | mask
		fail=1
	elif [ "${SQLERR_OK:-}" != 1 ] && grep -q 'SQLSTATE 42' "$work/out"; then
		echo "FAIL $name: red because of a SQL syntax/schema error, not the removed protection:"
		grep 'SQLSTATE 42' "$work/out" | head -2 | mask
		fail=1
	elif ! grep -F -q -- "--- FAIL: $want" "$work/out"; then
		echo "FAIL $name: red, but not on $want (the wrong attack caught it):"
		grep -- '--- FAIL' "$work/out" | head -3 | mask
		fail=1
	elif [ -n "$needle" ] && ! grep -F -q -- "$needle" "$work/out"; then
		echo "FAIL $name: $want went red, but not on [$needle]:"
		grep -F -- '_test.go' "$work/out" | head -3 | mask
		fail=1
	elif leak=$(grep -E '^[[:space:]]' "$work/out" | grep -E -i -o -e "$LEAK_RE" | head -1) && [ -n "$leak" ]; then
		# The failure text of a red run is what lands in a CI log: it must not
		# carry a token-shaped run or the base64 of one, whatever the mutant did.
		# Only the indented lines are the tests' own (t.Errorf and its
		# continuation lines); a mutant that prints the token itself writes
		# unindented lines, which are the mutant's doing and not a message.
		if [ "$expect" = leak ]; then
			echo "ok   $name: $want went red and LEAK_RE caught the leak (${#leak} chars)"
		else
			echo "FAIL $name: $want went red, but its output carries a token-shaped string (${#leak} chars) — a failing check must not print the credential"
			fail=1
		fi
	elif [ "$expect" = leak ]; then
		echo "FAIL $name: $want went red, but LEAK_RE did not catch the leak this mutant is built to carry"
		fail=1
	else
		echo "ok   $name: $want${needle:+ [$needle]} went red"
	fi
}

# mutate NAME FILE WANT FROM TO [NEEDLE] — one-edit mutant.
mutate() {
	begin "$1" "$3" "${6:-}"
	edit "$2" "$4" "$5"
	run
}

# Every shard proves the unmodified security tests work before accepting reds.
# baseline: the untouched tree is green, with nothing skipped.
if ! mutation_apply_only; then
	if ! (cd "$root" && go test -timeout 600s -count=1 -v -run '^TestIdentity_' ./test/security/ >"$work/base" 2>&1) ||
		grep -q -- '--- SKIP' "$work/base" || ! grep -q -- '^--- PASS: TestIdentity_' "$work/base"; then
		echo "FAIL baseline: attacks are not green (or skipped) on the unmodified tree"
		exit 1
	fi
	echo "ok   baseline: green, 0 skipped"
fi

T=TestIdentity_TokenNeverEscapesItsIssuance
# --- where a token must never appear
mutate token-stored-plain        token.go   $T 'h := sha256.Sum256([]byte(Reveal(token)))' 'h := append([]byte(Reveal(token)), sha256.Sum256(nil)[0])' 'surface "database"'
mutate last4-is-whole-token      repo.go    $T 'last4 := Last4(token)' 'last4 := Reveal(token)' 'surface "database"'
# The request log goes through internal/obs, whose writer blanks a token's random
# part on the rendered line. Two layers: what is logged, and the blanking. The
# first is held by the closed-shape log attack on its own (the line must be
# exactly the reason and the request's id); the next two mutants remove the
# blanking as well, and the token surface of the issuance attack must see the
# token on the log.
begin token-in-debug-log-closed-shape TestIdentity_AuthFailureLog/garbage_bearer
edit middleware.go 'logAuthFailure(r.Context(), logger, reason, requestID)' 'logAuthFailure(r.Context(), logger, reason, requestID+"|"+Reveal(token))'
run
NOSCRUB_FROM='func (s scrubWriter) Write(p []byte) (int, error) {'
NOSCRUB_TO='func (s scrubWriter) Write(p []byte) (int, error) { _ = tokenshape.Redact; return s.w.Write(p) }
func (s scrubWriter) writeScrubbed(p []byte) (int, error) {'
begin token-in-debug-log $T 'surface "debug-log"'
edit middleware.go 'logAuthFailure(r.Context(), logger, reason, requestID)' 'logAuthFailure(r.Context(), logger, reason, requestID+"|"+Reveal(token))'
edit internal/obs/obs.go "$NOSCRUB_FROM" "$NOSCRUB_TO"
run
begin body-in-debug-log $T 'surface "debug-log"'
edit middleware.go 'logAuthFailure(r.Context(), logger, reason, requestID)' 'logAuthFailure(r.Context(), logger, reason, requestID+"|"+Reveal(token)[7:])'
edit internal/obs/obs.go "$NOSCRUB_FROM" "$NOSCRUB_TO"
run
mutate db-error-is-401           middleware.go $T 'writeNotReady(w, requestID)' 'writeUnauthenticated(w, requestID)' 'dead database must answer 503'
# the database error Authenticate returns on a dead pool must never carry the
# token it was asked to check — the "db-down-error" surface must see it plain
mutate db-error-echoes-token     repo.go    $T 'return Principal{}, fmt.Errorf("identity: authenticate: %w", err)' 'return Principal{}, fmt.Errorf("identity: authenticate: %w: %s", err, Reveal(token))' 'surface "db-down-error"'
# stdout, the log package and slog's default — each on the path it was missed on
mutate issue-prints-token        repo.go    $T 'hash := HashToken(token)' 'fmt.Println(Reveal(token)); hash := HashToken(token)' 'surface "stdout+stderr+log"'
begin authenticate-log-printf-token $T 'surface "stdout+stderr+log"'
edit repo.go '"io"' '"io"
	"log"'
edit repo.go 'kind, err := ParseKind(token)' 'log.Printf("auth %s", Reveal(token)); kind, err := ParseKind(token)'
run
mutate authenticate-slog-default-token repo.go $T 'kind, err := ParseKind(token)' 'slog.Default().Info("auth", "t", Reveal(token)); kind, err := ParseKind(token)' 'surface "stdout+stderr+log"'
# the entropy behind the text: printed as hex, no text of the token anywhere
mutate generate-prints-raw-hex   token.go   $T 'return NewToken(fmt.Sprintf("%s_%s_%s", tokenPrefix, kind, lower(b32.EncodeToString(b)))), nil' 'fmt.Printf("%x\n", b); return NewToken(fmt.Sprintf("%s_%s_%s", tokenPrefix, kind, lower(b32.EncodeToString(b)))), nil' '/raw-bytes found'
# the issuance types' own hiding, one method at a time
mutate result-fmt-prints-token   repo.go    $T 'io.WriteString(f, r.String())' 'io.WriteString(f, Reveal(r.Token))' 'surface "IssueResult.fmt'
mutate result-gostring-leaks     repo.go    $T 'func (r IssueResult) GoString() string { return r.String() }' 'func (r IssueResult) GoString() string { return Reveal(r.Token) }' 'surface "IssueResult.GoString()"'
mutate result-logvalue-leaks     repo.go    $T 'return slog.StringValue(r.String())' 'return slog.StringValue(Reveal(r.Token))' 'surface "IssueResult.LogValue()"'
mutate result-marshaljson-leaks  repo.go    $T 'return nil, fmt.Errorf("identity: IssueResult must not be marshaled directly, call Response() first")' 'return []byte(`"` + Reveal(r.Token) + `"`), nil' 'surface "IssueResult.json"'
mutate response-string-leaks     repo.go    $T 'func (r IssueResponse) String() string   { return r.issueResponseRedacted() }' 'func (r IssueResponse) String() string   { return Reveal(r.Token) }' 'surface "IssueResponse.String()"'
mutate response-gostring-leaks   repo.go    $T 'func (r IssueResponse) GoString() string { return r.issueResponseRedacted() }' 'func (r IssueResponse) GoString() string { return Reveal(r.Token) }' 'surface "IssueResponse.GoString()"'
mutate response-format-leaks     repo.go    $T '_, _ = io.WriteString(f, r.issueResponseRedacted())' '_, _ = io.WriteString(f, Reveal(r.Token))' 'surface "IssueResponse.fmt'
mutate response-logvalue-leaks   repo.go    $T 'return slog.StringValue(r.issueResponseRedacted())' 'return slog.StringValue(Reveal(r.Token))' 'surface "IssueResponse.LogValue()"'

mutate response-marshaljson-leaks repo.go   $T 'return nil, fmt.Errorf("identity: IssueResponse must not be marshaled directly, call WireJSON() for the issuance response")' 'return []byte(`"` + Reveal(r.Token) + `"`), nil' 'a generic encoder serialized the issuance response'
mutate wirejson-drops-token      repo.go    $T 'Token:     Reveal(r.Token),' 'Token:     "",' 'the issuance response must carry the token'
# the Token type's own hiding — the layer that makes every wrapper safe by construction
mutate token-string-leaks        token.go   $T 'func (Token) String() string               { return redacted }' 'func (t Token) String() string { return Reveal(t) }' 'surface "Token.String()"'
mutate token-gostring-leaks      token.go   $T 'func (Token) GoString() string             { return redacted }' 'func (t Token) GoString() string { return Reveal(t) }' 'surface "Token.GoString()"'
mutate token-format-leaks        token.go   $T 'func (Token) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }' 'func (t Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Reveal(t))) }' 'surface "Token.fmt'
mutate token-marshaltext-leaks   token.go   $T 'func (Token) MarshalText() ([]byte, error) { return []byte(redacted), nil }' 'func (t Token) MarshalText() ([]byte, error) { return []byte(Reveal(t)), nil }' 'surface "Token.MarshalText()"'
mutate token-marshaljson-leaks   token.go   $T 'func (Token) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }' 'func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + Reveal(t) + `"`), nil }' 'surface "Token.MarshalJSON()"'
mutate token-logvalue-leaks      token.go   $T 'func (Token) LogValue() slog.Value         { return slog.StringValue(redacted) }' 'func (t Token) LogValue() slog.Value { return slog.StringValue(Reveal(t)) }' 'surface "Token.LogValue()"'
# the text held by value instead of behind a pointer: fmt reflects into unexported
# fields and prints a plain string there, so a token inside any struct leaks
begin token-text-held-by-value $T 'surface "holder'
edit token.go 'type Token struct{ p *string }' 'type Token struct{ s string }'
edit token.go 'func NewToken(text string) Token { return Token{p: &text} }' 'func NewToken(text string) Token { return Token{s: text} }'
edit token.go 'if t.p == nil {' 'if false {'
edit token.go 'return *t.p' 'return t.s'
edit token.go 'func (t Token) IsZero() bool { return t.p == nil || *t.p == "" }' 'func (t Token) IsZero() bool { return t.s == "" }'
run

# --- tenancy, uniformity, sponsor bound, immediacy: the named subtest
mutate org-from-url              middleware.go TestIdentity_TenantSwap/foreign_org_in_URL_is_404 'if err != nil || urlOrgID != p.OrgID {' 'if err != nil || (urlOrgID != p.OrgID && false) {'
mutate revoke-no-org-filter      repo.go    TestIdentity_TenantSwap/revoke_across_orgs 'AND org_id = $3 AND revoked_at IS NULL' 'AND $3::uuid IS NOT NULL AND revoked_at IS NULL'
mutate issue-no-org-check        repo.go    TestIdentity_TenantSwap/issue_for_a_principal_of_another_org 'WHERE id = $1 AND org_id = $2)' 'WHERE id = $1 AND $2::uuid IS NOT NULL)'
mutate revoked-distinguishable   middleware.go TestIdentity_UniformUnauthenticated/revoked 'reason := authReason(err)' 'reason := authReason(err); if reason == "revoked" { http.Error(w, "revoked", http.StatusForbidden); return }'
mutate agent-not-bounded         rights.go  TestIdentity_AgentNeverExceedsSponsor/role= 'if sponsorPerms[p] {' 'if sponsorPerms[p] || true {'
# `$3::text IS NOT NULL` is true for any scope: the protection is off, the SQL is valid
mutate sponsor-scope-ignored     repo.go    TestIdentity_AgentNeverExceedsSponsor/rights_in_one_scope_do_not_leak_into_another 'AND scope = $3`' 'AND $3::text IS NOT NULL`'
mutate deleted-principal-lives   repo.go    TestIdentity_RevocationAndDeletionAreImmediate/delete_principal_kind= 'if err := r.principalExists(ctx, kind, orgID, principalID); err != nil {' 'if err := error(nil); err != nil {'
mutate expiry-ignored            repo.go    TestIdentity_RevocationAndDeletionAreImmediate/expiry_set_to_the_past_takes_effect_on_the_next_call 'if expiresAt != nil && expiresAt.Before(time.Now()) {' 'if false {'
mutate revoked-ignored           repo.go    TestIdentity_RevocationAndDeletionAreImmediate/revoke_under_concurrent_load 'if revokedAt != nil {' 'if false {'

# --- the attacks' own guards: one mutant per empty branch that used to stay green,
# and one per protection that had no mutant at all. Each must go red on the
# named subtest.
U=TestIdentity_UniformUnauthenticated
A=TestIdentity_AgentNeverExceedsSponsor
# the "Bearer " scheme: matched exactly, and required
begin bearer-scheme-case-insensitive $U/lowercase_scheme
edit middleware.go 'if !strings.HasPrefix(h, prefix) {' 'if !strings.HasPrefix(strings.ToLower(h), strings.ToLower(prefix)) {'
edit middleware.go 'token := strings.TrimSpace(strings.TrimPrefix(h, prefix))' 'token := strings.TrimSpace(h[len(prefix):])'
run
mutate bearer-scheme-optional    middleware.go $U/token_without_scheme 'if !strings.HasPrefix(h, prefix) {' 'if false {'
# every failing path leaves one closed log line, and none leaks the header
mutate no-header-path-unlogged   middleware.go TestIdentity_AuthFailureLog/no_header 'logAuthFailure(r.Context(), logger, "malformed", requestID)' '_ = requestID'
mutate malformed-path-logs-header middleware.go TestIdentity_AuthFailureLog/token_without_scheme 'logAuthFailure(r.Context(), logger, "malformed", requestID)' 'logAuthFailure(r.Context(), logger, "malformed", requestID+"|"+r.Header.Get("Authorization"))'
begin malformed-path-logs-token-unscrubbed $T 'surface "debug-log"'
edit middleware.go 'logAuthFailure(r.Context(), logger, "malformed", requestID)' 'logAuthFailure(r.Context(), logger, "malformed", requestID+"|"+r.Header.Get("Authorization"))'
edit internal/obs/obs.go "$NOSCRUB_FROM" "$NOSCRUB_TO"
run
# the detector itself: base64 of a token after 1 leading byte (offset 1 mod 3)
mutate canary-blind-at-offset-1  internal/testutil/canary/canary.go $T 'for offset := 0; offset <= 2; offset++ {' 'for offset := 0; offset <= 2; offset++ { if offset == 1 { continue }' 'control: detector blind to base64'
# LEAK_RE's own branch above has never had to fire: the canary loop reports a
# hit by name and length only (identity_attack_test.go's own t.Errorf), so no
# mutant of internal/identity alone can ever reach "output carries a
# token-shaped string" — that branch has been dead code since it was written.
# Prove it lives, and that case-insensitivity is load-bearing: combine a real
# leak (token-stored-plain's own edit) with a mutation of the reporting line
# itself that prints a real, live token UPPERCASED — the second bug a leak's
# own report could someday have. Uppercased, the token's 52-char body no
# longer matches [a-z2-7] at all, and it is 52 characters short of the other
# alternative's 72-character floor: LEAK_RE would have missed this exact
# leak before the `grep -i` fix, and now must not. This run must be caught
# for THAT reason (EXPECT=leak), not scored a plain "ok".
begin leakre-catches-uppercased-leak $T 'surface "database"'
edit token.go 'h := sha256.Sum256([]byte(Reveal(token)))' 'h := append([]byte(Reveal(token)), sha256.Sum256(nil)[0])'
edit test/security/identity_attack_test.go 't.Errorf("canary %s found on surface %q (%d bytes of text; not printed)", c.name, s.label, len(s.text))' 't.Errorf("canary %s found on surface %q text=%s", c.name, s.label, strings.ToUpper(issued[identity.KindAgent].Token))'
run leak
# The same real leak as leakre-catches-uppercased-leak just above, but the
# reporting mutation renders it as 64 lowercase hex digits (a sha256 hash of
# the live token — 32 raw bytes, the exact shape LEAK_RE's third alternative
# exists for). Below the 72-character floor of the base64 alternative, and
# outside the 52-character base32 alphabet ([a-z2-7] excludes hex's own
# 0/1/8/9, present in a sha256 digest with overwhelming probability), so only
# `[0-9a-f]{64}` can catch it. Without a mutant pinned to it, that alternative
# could be deleted or narrowed and nothing here would notice.
begin leakre-catches-raw-hex $T 'surface "database"'
edit token.go 'h := sha256.Sum256([]byte(Reveal(token)))' 'h := append([]byte(Reveal(token)), sha256.Sum256(nil)[0])'
edit test/security/identity_attack_test.go '"encoding/base32"' '"crypto/sha256"
	"encoding/base32"'
edit test/security/identity_attack_test.go 't.Errorf("canary %s found on surface %q (%d bytes of text; not printed)", c.name, s.label, len(s.text))' 't.Errorf("canary %s found on surface %q hash=%x", c.name, s.label, sha256.Sum256([]byte(issued[identity.KindAgent].Token)))'
run leak
# The needle-mismatch branch above (a mutant's own `begin`/`mutate` NEEDLE not
# found in `$work/out`) is diagnostic, not a verdict: it greps the raw `go
# test -v` output for any line mentioning `_test.go`, which is every single
# t.Errorf/t.Fatalf line go test prints — so before `mask` it was just as able
# to print a live token as the "does not build" and "wrong attack" branches
# above it, and LEAK_RE's own check further below never runs for a needle
# miss (this branch returns first). Prove `mask` actually closes it: the same
# live-token edit as leakre-catches-uppercased-leak just above, but with a
# NEEDLE this run's output will never contain, so it is this branch — not the
# LEAK_RE branch `run leak` above already covers — that has to catch it.
begin diagnostics-are-masked $T 'this text is never printed by go test -timeout 600s -count=1 — forces the needle-mismatch branch'
edit token.go 'h := sha256.Sum256([]byte(Reveal(token)))' 'h := append([]byte(Reveal(token)), sha256.Sum256(nil)[0])'
edit test/security/identity_attack_test.go 't.Errorf("canary %s found on surface %q (%d bytes of text; not printed)", c.name, s.label, len(s.text))' 't.Errorf("canary %s found on surface %q text=%s", c.name, s.label, issued[identity.KindAgent].Token)'
if [ "$broken" != 1 ] && mutation_applied "$name"; then
	:
elif [ "$broken" != 1 ]; then
	prefail=$fail
	fail=0
	run >"$work/diag" 2>&1
	fail=$prefail
	if ! grep -qF -- 'went red, but not on [' "$work/diag"; then
		echo "FAIL diagnostics-are-masked: expected the needle-mismatch branch, the run took a different path"
		fail=1
	elif ! grep -Eqi -e "$LEAK_RE" "$work/out"; then
		echo "FAIL diagnostics-are-masked: control failed — go test's own -v output does not carry the live token this mutant relies on"
		fail=1
	elif grep -Eqi -e "$LEAK_RE" "$work/diag"; then
		echo "FAIL diagnostics-are-masked: the needle-mismatch diagnostic still printed a token-shaped string"
		fail=1
	else
		echo "ok   diagnostics-are-masked: needle-mismatch diagnostic carries no token-shaped string"
	fi
fi
# RequireOrgMatch with no Principal: 404, even for the nil UUID a zero Principal carries
mutate orgmatch-no-principal-passes middleware.go TestIdentity_TenantSwap/org_check_without_authentication_fails_closed 'p, ok := FromContext(r.Context())' 'p, _ := FromContext(r.Context()); ok := true'
# the sponsor-bound attack: org_id in both rights queries, the kind and sponsor checks
mutate sponsor-role-no-org       repo.go    $A/forged_principals_get_nothing 'WHERE user_id = $1 AND org_id = $2 AND scope = $3' 'WHERE user_id = $1 AND $2::uuid IS NOT NULL AND scope = $3'
mutate agent-grants-no-org       repo.go    $A/forged_principals_get_nothing 'FROM agent_grants WHERE agent_id = $1 AND org_id = $2' 'FROM agent_grants WHERE agent_id = $1 AND $2::uuid IS NOT NULL'
mutate effective-no-kind-check   repo.go    $A/forged_principals_get_nothing 'if p.Kind != KindAgent || p.SponsorUserID == nil {' 'if p.SponsorUserID == nil {'
mutate effective-no-sponsor-check repo.go   $A/forged_principals_get_nothing 'if p.Kind != KindAgent || p.SponsorUserID == nil {' 'if p.Kind != KindAgent {'
# an attack that expects "no rights" must first see rights where they exist: a
# sponsor that is never found, or one whose lookup always fails, looks the same
# as "no rights" to a test that swallows the error or has no control
mutate sponsor-never-found-scope repo.go    $A/rights_in_one_scope_do_not_leak_into_another 'WHERE user_id = $1 AND org_id = $2 AND scope = $3' 'WHERE user_id = $1 AND org_id = $2 AND scope = $3 AND false' 'control: the admin sponsor'"'"'s scope gives the agent no rights'
mutate sponsor-never-found-forged repo.go   $A/forged_principals_get_nothing 'WHERE user_id = $1 AND org_id = $2 AND scope = $3' 'WHERE user_id = $1 AND org_id = $2 AND scope = $3 AND false' 'control: the genuine agent lacks'
mutate sponsor-lookup-fails-scope repo.go   $A/rights_in_one_scope_do_not_leak_into_another 'if dbErr != nil {' 'if dbErr = errors.New("simulated backend failure"); dbErr != nil {' 'EffectiveAgentPermissions(ws:one)'
mutate sponsor-lookup-fails-demotion repo.go $A/sponsor_demoted 'if dbErr != nil {' 'if dbErr = errors.New("simulated backend failure"); dbErr != nil {' 'EffectiveAgentPermissions('
# a deleted principal of every kind, not only a service, must fail the uniform way
mutate deleted-user-lives-uniform repo.go   $U/deleted_user 'if err := r.principalExists(ctx, kind, orgID, principalID); err != nil {' 'if err := r.principalExists(ctx, kind, orgID, principalID); err != nil && kind != KindUser {'
# the token shape: anchored at both ends, and its kind must agree with the stored row
mutate tokenre-no-start-anchor   token.go   TestIdentity_ParseKindIsStrict/junk_before_the_token '`^keep_(' '`keep_('
mutate tokenre-no-end-anchor     token.go   TestIdentity_ParseKindIsStrict/junk_after_the_token '{%d})$`' '{%d})`'
# a sentinel wrapped with %w still satisfies errors.Is, so the malformed-input
# loop must reject it by == on ErrMalformedToken itself, not errors.Is — this
# mutant's own wrapping is exactly the shape the test's comment warns about
# (%w plus a hex encoding of the token in the error's own text).
mutate parsekind-wraps-sentinel  token.go   TestIdentity_ParseKindIsStrict/junk_after_the_token 'return "", ErrMalformedToken' 'return "", fmt.Errorf("%w: %x", ErrMalformedToken, Reveal(token))' 'error is not exactly ErrMalformedToken'
# a kind mismatch that fails as a database error (SQLSTATE 22012) is an error,
# but not the authentication verdict: RequireAuth would answer 503, not 401
mutate kind-mismatch-is-db-error repo.go    TestIdentity_TokenRowKindMustMatch/token_kind_ 'FROM tokens WHERE token_hash = $1 AND kind = $2' 'FROM tokens WHERE token_hash = $1 AND CASE WHEN kind = $2 THEN true ELSE 1/(char_length(kind)-char_length(kind)) = 0 END' 'not an authentication verdict'
# the length is fixed, not a minimum: a full token plus one in-alphabet character
mutate tokenre-open-length       token.go   TestIdentity_ParseKindIsStrict/an_in-alphabet_character_after_the_token '{%d})$`' '{%d,})$`' 'parsed as kind'
mutate authenticate-kind-ignored repo.go    TestIdentity_TokenRowKindMustMatch/token_kind_ 'FROM tokens WHERE token_hash = $1 AND kind = $2' 'FROM tokens WHERE token_hash = $1 AND $2::text IS NOT NULL'
# the Principal's context slot: closed to the caller, and never fail-open
mutate fromcontext-fail-open     principal.go TestIdentity_NoForgedPrincipal/contexts_built_by_the_caller_carry_none/empty 'return p, ok' 'return p, ok || true'
begin principal-key-guessable    TestIdentity_NoForgedPrincipal/contexts_built_by_the_caller_carry_none/string_key_principal
edit principal.go 'return context.WithValue(ctx, principalCtxKey{}, p)' 'return context.WithValue(ctx, "principal", p)'
edit principal.go 'p, ok := ctx.Value(principalCtxKey{}).(Principal)' 'p, ok := ctx.Value("principal").(Principal)'
run
# a token with junk after it that a fixed-size read would cut off: only the exact token may authenticate
mutate token-truncated-to-length middleware.go TestIdentity_HeaderFuzz/nul_byte 'return NewToken(token), true' 'if len(token) > 59 { token = token[:59] }; return NewToken(token), true'
# the pool that stands in for a dead database must actually have been built: a
# pool that failed to build is a nil pointer, not a dead database
mutate dead-pool-build-unchecked test/security/identity_attack_test.go TestIdentity_AuthFailureLog 'dead, err := pgxpool.New(ctx, os.Getenv("KEEP_DATABASE_URL"))' 'dead, err := pgxpool.New(ctx, "postgres://%zz")' 'cannot build the pool'
# the database's refusals must be integrity violations: a statement that does not
# run at all (a typo) is also an error, and is not a refusal
SQLERR_OK=1
mutate refusal-by-typo-check     test/security/identity_attack_test.go TestIdentity_TenantSwap/database_refuses_cross-org_rows/permission_outside_the_closed_set '(id, org_id, agent_id, permission) VALUES ($1,$2,$3,'"'"'read_secret'"'"')' '(id, org_id, agent_id, permissionx) VALUES ($1,$2,$3,'"'"'read_secret'"'"')' 'refused for the wrong reason'
mutate refusal-by-typo-role      test/security/identity_attack_test.go TestIdentity_TenantSwap/database_refuses_cross-org_rows/role_outside_the_closed_set '(id, org_id, user_id, scope, role) VALUES ($1,$2,$3,'"'"'org:y'"'"'' '(id, org_id, user_id, scope, rolex) VALUES ($1,$2,$3,'"'"'org:y'"'"'' 'refused for the wrong reason'
SQLERR_OK=0

mutation_shard_finish
exit $fail
