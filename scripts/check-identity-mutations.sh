#!/bin/sh
# Proves the identity tests can fail (this package's own acceptance requirement, ADR-001 §6, tenancy
# model §1/§4): in a scratch copy of the tree, switch off one property of
# internal/identity at a time and require `go test ./internal/identity/` to
# go red. A property whose removal leaves the tests green is not tested.
#
# Unlike pkg/fingerprint's or pkg/execpolicy's own mutation scripts,
# internal/identity's tests need a real PostgreSQL (see repo_test.go's
# testDB — no mocking, CONTRIBUTING.md) and the
# schema must already be migrated: KEEP_DATABASE_URL must point at an
# already-migrated database before this script runs (`go run
# ./cmd/keep-server migrate up`, same as .gitlab-ci.yml's `test` job). Every
# mutation below only changes internal/identity's Go source, never the
# schema, so one migration up front is enough for every mutant that follows
# — they all read/write the same tables the real code does.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"

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
mutation_apply_only || module=$(cd "$root" && go list -m)

if [ -z "${KEEP_DATABASE_URL:-}" ] && ! mutation_apply_only; then
	echo "FAIL check-identity-mutations: KEEP_DATABASE_URL is not set — internal/identity's tests would silently skip (t.Skip), not fail, which this script must never report as red"
	exit 1
fi

fail=0
# edit SRC FROM TO: print SRC with the first literal occurrence of FROM
# replaced by TO; exit 1 if FROM is not there.
edit() {
	awk -v from="$2" -v to="$3" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$1"
}

# The packages every mutant is judged against: identity itself, plus the
# small packages its token guarantees lean on (obs scrubs log output,
# tokenshape says what a token looks like, reqid keeps a token out of the
# request id it echoes).
pkgs="./$pkg/ ./internal/obs/ ./internal/tokenshape/ ./internal/reqid/"

# mutate NAME FILE FROM TO [FROM2 TO2]: replace the first literal occurrence
# of FROM (and, if given, of FROM2) with TO. FILE is relative to
# internal/identity, or to the repo root when it contains a slash or starts
# with a dot.
mutate() {
	name=$1 file=$2 from=$3 to=$4
	case $file in */* | .*) src=$file ;; *) src=$pkg/$file ;; esac
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! edit "$root/$src" "$from" "$to" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	if [ $# -ge 6 ]; then
		cp "$work/tree/$src" "$work/second"
		if ! edit "$work/second" "$5" "$6" >"$work/tree/$src"; then
			echo "FAIL $name: second edit did not apply — the source changed, update this script"
			fail=1
			return
		fi
	fi
	mutation_applied "$name" && return
	want_pkg=$(dirname "$src")
	# Identity's generator/parse tests witness the shared length constant;
	# its token leak tests also pin the scanner configuration.
	case "$name" in
		tokenshape-bodylen-drifts|gitleaks-rule-narrowed) want_pkg=$pkg ;;
	esac
	# shellcheck disable=SC2086
	if (cd "$work/tree" && go test -json -timeout 120s -count=1 $pkgs >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! mutation_package_test_failed "$work/out" "$module/$want_pkg"; then
		# Red because the mutant does not build, or every test skipped, is
		# not a failing test.
		echo "FAIL $name: mutant did not reach a failing test in the expected package (build/setup error, unrelated failure, or a silent skip?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

# AC red run (1): a token is stored as its own bytes instead
# of SHA-256(token) — the leak test (TestTokenNeverStoredPlaintext) and the
# canary lifecycle test must catch a plaintext-shaped tokens.token_hash.
mutate hash-not-token       repo.go 'hash := HashToken(token)' 'hash := []byte(Reveal(token))'
# AC red run (2): the org-match middleware stops checking the
# Principal's own OrgID and accepts whatever org_id the URL claims — the
# isolation test must reject this (404 for a foreign org, never a silent
# pass-through).
mutate org-from-url         middleware.go 'urlOrgID != p.OrgID' 'urlOrgID == p.OrgID && false'
# AC red run (3): an agent's permissions stop being
# intersected with its sponsor's role-derived permissions — the rights
# test must show the agent exceeding its sponsor.
mutate no-sponsor-intersection rights.go 'if sponsorPerms[p] {' 'if true || sponsorPerms[p] {'
# a revoked token's revoked_at is never checked — Authenticate would keep
# accepting it forever.
mutate no-revoke-check      repo.go 'if revokedAt != nil {' 'if false {'
# an expired token's expires_at is never checked.
mutate no-expiry-check      repo.go 'if expiresAt != nil && expiresAt.Before(time.Now()) {' 'if false {'
# every agent's default grants quietly include rotate — this package's
# own design decision is explicit that rotate and create_ref require an
# explicit grant, never a default.
mutate default-grants-include-rotate rights.go 'PermDeploy:       true,' 'PermDeploy: true, PermRotate: true,'
# the viewer role quietly grants deploy — the role vocabulary in
# rolePermissions is this package's own decision (rights.go's doc) and its
# closedness is exactly what TestAgentPermissionsNeverExceedsSponsor pins.
mutate viewer-role-includes-deploy   rights.go 'RoleViewer: {PermReadMetadata: true},' 'RoleViewer: {PermReadMetadata: true, PermDeploy: true},'
# Revoke stops filtering by the caller's own org — a caller from org B
# could revoke a token issued in org A. $3 = $3 is a tautology that keeps
# the placeholder referenced (so the argument count pgx expects still
# matches) while making the org comparison always true.
mutate revoke-no-org-filter repo.go \
	'WHERE id = $2 AND org_id = $3 AND revoked_at IS NULL' \
	'WHERE id = $2 AND ($3 = $3 OR org_id = $3) AND revoked_at IS NULL'
# a token whose principal (user/agent/service) has since been deleted keeps
# authenticating forever — Authenticate's post-lookup principalExists check
# never actually runs.
mutate deleted-principal-still-authenticates repo.go \
	'if err := r.principalExists(ctx, kind, orgID, principalID); err != nil {' \
	'if err := r.principalExists(ctx, kind, orgID, principalID); false && err != nil {'
# the deleted-principal check silently stops applying to KindUser tokens
# specifically — TestAuthenticateRejectsDeletedPrincipal's table test over
# all three kinds is what catches this; the old service-only test stayed
# green against it (review round 2, blocker #4).
mutate deleted-principal-check-skips-user repo.go \
	'if err := r.principalExists(ctx, kind, orgID, principalID); err != nil {' \
	'if err := r.principalExists(ctx, kind, orgID, principalID); kind != KindUser && err != nil {'
# No deleted-principal-check-skips-agent mutation: KindAgent's deletion is
# doubly covered by two INDEPENDENT checks — principalExists above, and
# Authenticate's own agent branch separately re-reading sponsor_user_id
# from the agents table, which returns pgx.ErrNoRows on its own once the
# agent row is gone. Verified live, 24.09, on a scratch copy: disabling
# principalExists alone for KindAgent (mirroring deleted-principal-check-skips-user
# above) leaves TestAuthenticateRejectsDeletedPrincipal's "a" subtest
# green, because the second check still catches it; disabling only the
# second check (guarding it with `kind != KindAgent`, the same technique)
# leaves it green too, because principalExists runs first and already
# rejects it. Neither is a real gap — the property still holds against the
# real code, and disabling either check alone isn't a property this test
# suite can observe in isolation, so per this script's own rule ("a
# property whose removal leaves the tests green is not tested") there's no
# single-mutation red run to add here without disabling both checks in one
# edit, which check-identity-mutations.sh's from/to model can't express.
# deleted-principal-still-authenticates above (which disables
# principalExists for every kind at once) still red-runs on this file via
# its "s" and "u" subtests.
# sponsorRole stops filtering by org — the same (user_id, scope) pair from
# a different organization would resolve to a role that isn't theirs.
mutate sponsor-role-any-org repo.go \
	'WHERE user_id = $1 AND org_id = $2 AND scope = $3' \
	'WHERE user_id = $1 AND ($2 = $2 OR org_id = $2) AND scope = $3'
# agentExplicitGrants stops filtering by org — a grant row would be
# readable under any organization, not just the one it was written in.
mutate agent-grants-any-org repo.go \
	'WHERE agent_id = $1 AND org_id = $2' \
	'WHERE agent_id = $1 AND ($2 = $2 OR org_id = $2)'
# RequireAuth's auth-failure debug log picks up the raw token — proves the
# log-leak test (TestAuthFailuresNeverLeakTokenToLog) actually inspects the
# rendered log line rather than trusting obs's allow-list alone: request_id
# is an allowed key, so a value smuggled onto it sails straight through.
mutate auth-failure-logs-token middleware.go \
	'logAuthFailure(r.Context(), logger, reason, requestID)' \
	'logAuthFailure(r.Context(), logger, reason, requestID+" token="+Reveal(token))'
# a database failure inside Authenticate gets answered as 401 like any
# ordinary bad token, instead of 503 — a down dependency would look like
# every caller's token suddenly went invalid.
mutate backend-error-answered-401 middleware.go \
	'if !errors.Is(err, ErrUnauthenticated) {' \
	'if false && !errors.Is(err, ErrUnauthenticated) {'
# IssueResult's MarshalJSON stops refusing to serialize and instead hands
# the real token back as valid JSON — TestIssueResultNeverLeaksThroughJSONLogOrFormat
# must catch this the moment json.Marshal succeeds.
mutate issue-result-marshaljson-leaks repo.go \
	'return nil, fmt.Errorf("identity: IssueResult must not be marshaled directly, call Response() first")' \
	'return []byte(`"` + Reveal(r.Token) + `"`), nil'
# IssueResult.LogValue stops redacting and hands slog the raw token instead
# of the redacted string — proves the log-leak assertion actually inspects
# the rendered log line, not just that a LogValue method exists.
mutate issue-result-logvalue-leaks repo.go \
	'return slog.StringValue(r.String())' \
	'return slog.StringValue(Reveal(r.Token))'
# IssueResult.Format stops redacting for non-Stringer verbs (%d, %t) —
# proves the fmt-leak assertion covers those verbs and not only %v/%+v.
mutate issue-result-format-leaks repo.go \
	'_, _ = io.WriteString(f, r.String())' \
	'_, _ = io.WriteString(f, Reveal(r.Token))'
# IssueResponse.LogValue stops redacting — the one type allowed to carry a
# token over JSON must still redact it under slog.
mutate issue-response-logvalue-leaks repo.go \
	'return slog.StringValue(r.issueResponseRedacted())' \
	'return slog.StringValue(Reveal(r.Token))'
# RequireAuth's success path starts writing the token to stdout/stderr —
# TestRequireAuthSuccessNeverLeaksTokenToLog is the only test that would
# catch this (TestRequireAuthAttachesPrincipalOnSuccess passes a nil logger
# and never captures stdout, so it stays green against this on its own).
mutate auth-success-logs-token middleware.go \
	'next.ServeHTTP(w, r.WithContext(withContext(r.Context(), p)))' \
	'println(Reveal(token)); next.ServeHTTP(w, r.WithContext(withContext(r.Context(), p)))'
# The 503 (backend-error) branch starts writing the token to stdout/stderr
# — TestRequireAuthNotReadyNeverLeaksTokenToLog is the only test that would
# catch this.
mutate backend-error-logs-token middleware.go \
	'writeNotReady(w, requestID)' \
	'println(Reveal(token)); writeNotReady(w, requestID)'

# ── a token's redaction must not depend on where the value sits ──────────
# (nested forms, the Token type, log output scrub, request ids, the scanner
# rule). Several layers overlap on purpose — Token's Format, String and
# LogValue, and obs's output scrub, each catch what another would — so a
# mutant switches off one layer whose absence the tests can see: the layer
# that is the only one guarding some shape.
# Token starts holding its text by value instead of behind a pointer: fmt
# prints a struct's unexported fields by reflection and calls no method
# there, so a value-held text prints as itself when a Token sits inside an
# unexported field of another struct.
mutate token-held-by-value token.go \
	'type Token struct{ p *string }' \
	'type Token struct{ p *string; text string }' \
	'func NewToken(text string) Token { return Token{p: &text} }' \
	'func NewToken(text string) Token { return Token{p: &text, text: text} }'
# Token.Format stops redacting.
mutate token-format-leaks token.go \
	'func (Token) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }' \
	'func (t Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Reveal(t))) }'
# Token's JSON encoding stops redacting (a Token inside a map or a struct
# that is marshaled).
mutate token-marshaljson-leaks token.go \
	'func (Token) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }' \
	'func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + Reveal(t) + `"`), nil }'
# Token.LogValue stops redacting; the bare-slog-handler leg of the leak
# tests must catch it even though obs would have scrubbed the line.
mutate token-logvalue-leaks token.go \
	'func (Token) LogValue() slog.Value         { return slog.StringValue(redacted) }' \
	'func (t Token) LogValue() slog.Value { return slog.StringValue(Reveal(t)) }'
# IssueResponse goes back to being marshalable: a struct that merely
# contains one, passed to json.Marshal or a logger, carries the token out.
mutate issue-response-marshaljson-leaks repo.go \
	'return nil, fmt.Errorf("identity: IssueResponse must not be marshaled directly, call WireJSON() for the issuance response")' \
	'return r.WireJSON()'
# WireJSON stops writing the token: the issuance response would show the
# holder "[REDACTED]" instead of their credential.
mutate wirejson-drops-token repo.go \
	'Token:     Reveal(r.Token),' \
	'Token:     r.Token.String(),'
# obs stops scrubbing its output: a token-shaped value under an allowed
# "*_id" key, in a message, or nested in a struct reaches the log.
mutate obs-scrub-off internal/obs/obs.go \
	'slog.NewJSONHandler(scrubWriter{w}, ' \
	'slog.NewJSONHandler(w, '
# obs scrubs only short records: a token after 4 KB of message, value or
# stack goes out as is.
mutate obs-scrub-skips-long-records internal/obs/obs.go \
	'if _, err := s.w.Write(tokenshape.Redact(' \
	'if len(p) >= 512 { return s.w.Write(p) }; if _, err := s.w.Write(tokenshape.Redact('
# reqid accepts request ids long enough to hold a token's random part again.
mutate reqid-accepts-token-length internal/reqid/reqid.go \
	'{1,36}$`)' \
	'{1,64}$`)'
# tokenshape's pattern stops matching real tokens (length off by one).
mutate tokenshape-pattern-too-long internal/tokenshape/tokenshape.go \
	'const Pattern = `(?i)[a-z2-7]{52,}`' \
	'const Pattern = `(?i)[a-z2-7]{53,}`'
# tokenshape matches exactly 52 characters again: a token written against
# other characters of its alphabet leaves its tail in the log.
mutate tokenshape-exact-length internal/tokenshape/tokenshape.go \
	'const Pattern = `(?i)[a-z2-7]{52,}`' \
	'const Pattern = `(?i)[a-z2-7]{52}`'
# the length constant drifts from what GenerateToken produces.
mutate tokenshape-bodylen-drifts internal/tokenshape/tokenshape.go \
	'const BodyLen = 52' \
	'const BodyLen = 51'
# the scanner rule is narrowed to agent tokens only: a service or user
# token committed to the repo would no longer be flagged.
mutate gitleaks-rule-narrowed .gitleaks.toml \
	"regex = '''keep_[asu]_[a-z2-7]{52}'''" \
	"regex = '''keep_a_[a-z2-7]{52}'''"
# the allow-list of log keys grows without the pinned list being edited.
mutate obs-allowlist-grows internal/obs/obs.go \
	'"auth_reason": true,' \
	'"auth_reason": true, "token": true,'

# attributes bound with With() skip the allow-list.
mutate obs-withattrs-skips-allowlist internal/obs/obs.go \
	'return &Handler{next: h.next.WithAttrs(kept)}' \
	'return &Handler{next: h.next.WithAttrs(attrs)}'
# a new key-name shape is let through beside the pinned ones.
mutate obs-suffix-rule-widens internal/obs/obs.go \
	'return strings.HasSuffix(k, "_id") || strings.HasSuffix(k, "_name")' \
	'return strings.HasSuffix(k, "_id") || strings.HasSuffix(k, "_name") || strings.HasSuffix(k, "_value")'
# a Token used as a map key is written out (encoding/json uses MarshalText
# for keys, a path separate from MarshalJSON).
mutate token-marshaltext-leaks token.go \
	'func (Token) MarshalText() ([]byte, error) { return []byte(redacted), nil }' \
	'func (t Token) MarshalText() ([]byte, error) { return []byte(Reveal(t)), nil }'
# a Token can be decoded from JSON text.
mutate token-decodes-from-json token.go \
	'func (*Token) UnmarshalJSON([]byte) error  { return errTokenNoDecode }' \
	'func (t *Token) UnmarshalJSON(b []byte) error { *t = NewToken(string(b)); return nil }'
# the malformed-token rejection echoes what was presented.
mutate authenticate-echoes-presented-token repo.go \
	'return Principal{}, ErrTokenMalformed' \
	'return Principal{}, fmt.Errorf("%w: %s", ErrTokenMalformed, Reveal(token))'
# the issuance response loses a field other than the token.
mutate wirejson-drops-scope repo.go \
	'Scope:     r.Scope,' \
	'Scope:     "",'

# shellcheck disable=SC2086
if mutation_apply_only; then
	:
elif (cd "$root" && go test -timeout 120s -count=1 $pkgs >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
