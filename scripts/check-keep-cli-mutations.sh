#!/bin/sh
# Proves the cmd/keep tests can fail (ADR-001 §3.4 — no "show value"
# command, threat model §4.1-4.4): in a scratch copy of the
# tree, switch off one property of cmd/keep at a time and require `go test
# ./cmd/keep/` to go red. A property whose removal leaves the tests green is
# not tested. Each ordinary mutant must fail its mapped whole-parent witness;
# all subtests remain selected, and the final baseline still runs the full package.
#
# cmd/keep's e2e tests need a real PostgreSQL (CONTRIBUTING.md — never
# mocked) behind a real Keep Server, and the schema must already be
# migrated: KEEP_DATABASE_URL must point at an already-migrated database
# before this script runs (`go run ./cmd/keep-server migrate up`, same as
# .gitlab-ci.yml's `test` job). cmd/keep/cli_e2e_test.go's tests call t.Skip
# when KEEP_DATABASE_URL is unset — that would make every mutation below
# silently "pass" this script (no failing test, just a skip), so this check
# refuses to run at all without it, same guard as check-identity-mutations.sh.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change.
# Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/cli-mutation-witnesses.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=cmd/keep

if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo "FAIL check-keep-cli-mutations: KEEP_DATABASE_URL is not set — cmd/keep's e2e tests would silently run zero tests (each DB test skips), not fail, which this script must never report as red"
	exit 1
fi

fail=0
# edit SRC FROM TO: print SRC with the first literal occurrence of FROM
# replaced by TO; exit 1 if FROM is not there. Never pass a FROM/TO
# containing a backslash escape (e.g. \n) — awk's -v assignment unescapes
# it before the literal-substring match ever runs, so it silently fails to
# find text that is visibly right there in the source.
edit() {
	awk -v from="$2" -v to="$3" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$1"
}

# mutate NAME FILE FROM TO [FROM2 TO2]: replace the first literal occurrence
# of FROM (and, if given, of FROM2) with TO. FILE is relative to cmd/keep.
mutate() {
	name=$1 src=$pkg/$2 from=$3 to=$4
	want=${metadata_witness:-}
	if [ -z "$want" ]; then
		if ! want=$(cli_mutation_witness "$name"); then
			echo "FAIL $name: designated witness is not mapped"
			fail=1
			return
		fi
	fi
	case "$want" in
		Test*) ;;
		*) echo "FAIL $name: unsupported witness"; fail=1; return ;;
	esac
	case "$want" in
		*[!A-Za-z0-9_]*) echo "FAIL $name: unsupported witness"; fail=1; return ;;
	esac
	if [ -n "${metadata_witness:-}" ] && ! mutation_apply_only; then
		if ! (cd "$root" && go test -timeout 60s -count=1 -v -run "^$metadata_witness$" ./$pkg >"$work/control" 2>&1) || grep -q -- '--- SKIP' "$work/control"; then
			echo "FAIL $name: designated positive control did not pass without skips"
			fail=1
			return
		fi
	fi
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! edit "$root/$src" "$from" "$to" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	if [ "$name" = json-control-escape-delete ]; then
		python3 - "$work/tree/$src" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
source = p.read_text()
start = source.index('// encoding/json already escapes C0')
end = source.index('// cell makes', start)
source = source[:start] + source[end:]
for dependency in ['unicode', 'unicode/utf16', 'unicode/utf8']:
    source = source.replace('\t"' + dependency + '"\n', '')
p.write_text(source)
PY
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
	if (cd "$work/tree" && go test -timeout 120s -count=1 -v -run "^$want$" ./$pkg/... >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif ! grep -q -F -- "--- FAIL: $want (" "$work/out" || grep -q -E -- '--- SKIP|\[build failed\]|\[setup failed\]|panic: test timed out' "$work/out" || mutation_infrastructure_failed "$work/out" || { [ -n "${metadata_witness:-}" ] && ! grep -q -F -- "$metadata_marker" "$work/out"; }; then
		# Red because the mutant does not build, or every test skipped
		# (no KEEP_DATABASE_URL propagated into the copy), is not a
		# failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error, or a silent skip?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

# Metadata mutants must fail their own assertion; an unrelated failing test
# or an infrastructure failure is not evidence that JSON escaping was tested.
metadata_mutate() {
	metadata_witness=$1 metadata_marker=$2
	shift 2
	mutate "$@"
	metadata_witness= metadata_marker=
}

# AC red run (1): --debug stops redacting the Authorization header — the
# canary-based leak test (TestCLI_TokenNeverLeaksToStdoutStderrOrDebug) must
# catch the real token appearing in a debug trace.
mutate debug-leaks-authorization client.go \
	'if strings.EqualFold(k, "Authorization") {' \
	'if false {'
# AC red run (2): a 0644 (or otherwise group/other-readable) token file
# stops being refused — TestResolveToken_RefusesWidePermissions must catch
# this exactly as the card's AC specifies.
mutate wide-permission-accepted token.go \
	'if info.Mode().Perm()&0o077 != 0 {' \
	'if info.Mode().Perm()&0o077 != 0 && false {'
# Remove the permission guard completely, including its unused mode value.
mutate wide-permission-guard-removed token.go \
	'info, err := f.Stat()' '_, err = f.Stat()' \
	'if info.Mode().Perm()&0o077 != 0 {' 'if false {'
# narrower than (2): the check keeps refusing other-readable files but
# stops refusing group-readable ones — TestResolveToken_RefusesGroupReadableEvenWithoutOtherAccess
# is the only test that would catch this (the 0644 case above still trips
# the "other" bit).
mutate group-readable-accepted token.go \
	'if info.Mode().Perm()&0o077 != 0 {' \
	'if info.Mode().Perm()&0o007 != 0 {'
# runLogin's temp file stops being created at tokenFilePerm — the file is
# renamed into place afterward with no further chmod, so this is the only
# place the mode is set; TestRunLogin_WritesFileWithOwnerOnlyMode and
# TestRunLogin_FixesModeOfPreExistingLooseFile both check the mode the
# rename target ends up at.
mutate login-skips-chmod-fixup token.go \
	'if err := tmp.Chmod(tokenFilePerm); err != nil {' \
	'if err := tmp.Chmod(0o644); err != nil {'
# Login success must not echo either the stdin value or the path argument.
mutate login-echoes-token main.go \
	'fmt.Fprintln(stderr, "keep: token written")' \
	'fmt.Fprintln(stderr, "keep: token written", token)'
mutate login-echoes-token-file main.go \
	'fmt.Fprintln(stderr, "keep: token written")' \
	'fmt.Fprintln(stderr, "keep: token written", *tokenFile)'
# A credential pasted as the command (including a leading dash) stays private.
mutate unknown-command-echoes-argument main.go \
	'"keep: unknown command' 'cmd + "keep: unknown command'
# Both filesystem error types must be hidden, including wrapped errors.
mutate path-error-printed main.go \
	'errors.As(err, &pathErr) || errors.As(err, &linkErr)' \
	'(false && errors.As(err, &pathErr)) || errors.As(err, &linkErr)'
mutate link-error-printed main.go \
	'errors.As(err, &pathErr) || errors.As(err, &linkErr)' \
	'errors.As(err, &pathErr) || (false && errors.As(err, &linkErr))'
# Remove the entire sanitization effect, rather than only one error type.
mutate filesystem-error-guard-noop main.go \
	'err = errors.New("file_error: filesystem operation failed")' \
	'_ = err'
mutate token-permission-error-echoes-path token.go \
	'errors.New("refusing to read token file: permissions allow access beyond its owner — chmod 600 it or run `keep login` again")' \
	'fmt.Errorf("refusing to read %s: wide permissions", path)'
mutate token-empty-error-echoes-path token.go \
	'errors.New("token file is empty — run `keep login`")' \
	'fmt.Errorf("%s is empty", path)'
mutate login-help-fails main.go \
	'if errors.Is(err, flag.ErrHelp) {' \
	'if false && errors.Is(err, flag.ErrHelp) {'
# the client-side by-name resolver stops returning secret_not_found on a
# miss and instead returns a nil error with a zero-value secret —
# TestCLI_UnknownNameAnswersSecretNotFound must catch a lookup that silently
# "succeeds" instead of the no-oracle secret_not_found shape.
mutate name-resolution-swallows-miss commands.go \
	'return secret{}, errSecretNameNotFound()' \
	'return secret{}, nil'
# --server (or KEEP_SERVER) pointing at a real host over plain http stops
# being refused — TestGlobalOptsNewClientRefusesInsecureServer must catch a
# bearer token that would otherwise go out over that link in plaintext.
# `&& false` rather than replacing the whole condition with `if false`: `su`
# is declared by the url.Parse line just above and used nowhere else, so a
# mutation that drops the requireSecureURL(su) call entirely would leave it
# unused and fail to build — which this script would then (correctly) refuse
# to count as the guard "failing", since a build error isn't a failing test.
mutate insecure-server-accepted main.go \
	'if err := requireSecureURL(su); err != nil {' \
	'if err := requireSecureURL(su); err != nil && false {'
# CheckRedirect's manual policy stops re-adding net/http's own 10-redirect
# cap — TestClientCheckRedirectCapsRedirectCount must catch a
# self-redirecting server being followed until the client's Timeout instead
# of a bounded number of hops.
mutate redirect-cap-removed client.go \
	'if len(via) >= 10 {' \
	'if false {'
# a flag-then-positional login token (`keep login --token-file PATH TOKEN`)
# stops being rejected — TestRunLoginSubcommandRejectsTokenAfterFlags must
# catch the leftover token silently falling through to the stdin path
# instead of failing loudly.
mutate login-drops-flagged-token-arg main.go \
	'if extra := fs.Args(); len(extra) > 0 {' \
	'if extra := fs.Args(); len(extra) > 0 && false {'
# the leftover-argument error message goes back to printing the argument
# values themselves (the token, for the flag-then-positional case) instead
# of just their count — TestRunLoginSubcommandRejectsTokenAfterFlags's
# canary check must catch the token reappearing in stderr.
mutate login-leaks-extra-args-in-error main.go \
	'"keep login: %d unexpected argument(s) after flags' '"keep login: unexpected argument(s) %v after flags' \
	'len(extra))' 'extra)'
# login's FlagSet output goes back to stderr — a leading-dash token is then
# echoed by the stdlib's own "flag provided but not defined: -TOKEN" text;
# TestRunLoginSubcommandLeadingDashTokenNotEchoed's canary check must catch it.
mutate login-flagset-output-to-stderr main.go \
	'fs.SetOutput(io.Discard)' 'fs.SetOutput(stderr)'
# login stops recognising the unknown-flag parse error, so a leading-dash
# token gets the generic "could not parse" text again instead of the
# cause-naming message; TestRunLoginSubcommandLeadingDashTokenNamesCause
# must catch it.
mutate login-dash-token-cause-unnamed main.go \
	'strings.HasPrefix(err.Error(), "flag provided but not defined")' 'strings.HasPrefix(err.Error(), "flag provided but not defined-never")'
# isLoopbackHost itself stops distinguishing a loopback host from a real
# one — insecure-server-accepted above only disables the one call site in
# newClient, so the classification logic underneath (requireSecureURL,
# TestRequireSecureURL) had no mutation of its own until this line.
mutate isloopback-always-true client.go \
	'if host == "localhost" {' \
	'if true || host == "localhost" {'
# --debug starts tracing the raw endpoint instead of the redacted URL —
# --server (or KEEP_SERVER) can carry a userinfo password, and endpoint is
# built straight from the caller's baseURL, so this is exactly the leak
# TestClientDebugTraceRedactsServerUserinfo exists to catch.
mutate debug-trace-leaks-server-userinfo client.go \
	'method, req.URL.Scheme, req.URL.Host, redactedHeaderDump' \
	'method, endpoint, "", redactedHeaderDump'
# the same-host https->http redirect-downgrade guard (CheckRedirect calling
# requireSecureURL on every redirect target) stops being enforced —
# TestClientRefusesRedirectToInsecureHost must catch a bearer token that
# would otherwise follow a downgraded redirect in plaintext.
mutate redirect-downgrade-unchecked client.go \
	'if err := requireSecureURL(req.URL); err != nil {' \
	'if err := requireSecureURL(req.URL); err != nil && false {'
# `keep login`'s positional-token warning (visible via `ps`/shell history)
# stops printing — TestCLI_LoginWithPositionalTokenWarns must catch the
# backward-compatible positional form going silent about that exposure.
mutate login-positional-warning-silenced main.go \
	'_, _ = fmt.Fprintln(stderr, "keep login: passing the token as an argument is visible to other local users via `ps` and is kept in shell history — pipe it on stdin instead, e.g. `keep login < token-file`")' \
	'_ = stderr'
# a malformed --server (e.g. a userinfo password plus a stray space in the
# host) starts reporting url.Parse's own error text again, which repeats the
# raw --server value — TestGlobalOptsNewClientServerParseErrorDoesNotLeakUserinfo
# must catch that regression.
mutate server-parse-error-leaks-userinfo main.go \
	'return nil, errors.New("--server: invalid URL")' \
	'return nil, fmt.Errorf("--server: %w", err)'

# --debug starts tracing response bodies — TestCLI_MetadataCanaryStaysOutOfDebugTrace
# must see the description canary in stderr and go red.
mutate debug-traces-response-body client.go \
	'respBody, err := io.ReadAll(resp.Body)' \
	'respBody, err := io.ReadAll(resp.Body); c.debugf("body: %s", respBody)'

# (list-failure-rewritten-per-name retired: it relied on the not-found message
# quoting the requested name, which differed between a foreign org, a miss and
# an unknown org. The message no longer carries the name at all —
# secret-name-echoed-in-not-found below guards that, and the cross-org test
# still compares the whole stderr.)
# the CLI swallows a refused token file and carries on with an empty token —
# the resolveToken unit tests stay green (they call it directly), only
# TestCLI_RefusesWideOpenTokenFileAndNeverCallsTheServer sees the server
# receiving a request it must never get.
mutate refused-token-file-swallowed main.go \
	'tok, err := resolveToken(getenv, o.tokenFile)' \
	'tok, err := resolveToken(getenv, o.tokenFile); if err != nil { tok, err = "", nil }'

# KEEP_SERVER becomes the --server flag default again — flag prints defaults
# on -h and on parse errors, so a userinfo password in it reaches the
# terminal; TestHelpAndParseErrorsDoNotPrintKeepServerPassword must catch it.
mutate server-env-as-flag-default main.go \
	'fs.StringVar(&o.server, "server", "",' \
	'fs.StringVar(&o.server, "server", getenv("KEEP_SERVER"),' \
	'scopeLevel, scopeID := bindScopeFlags(fs)' \
	'fs.SetOutput(os.Stderr); scopeLevel, scopeID := bindScopeFlags(fs)'
# a redirect to another host:port stops being refused — net/http would carry
# Authorization along; TestClientRefusesRedirectToDifferentHost must catch it.
mutate redirect-host-unchecked client.go \
	'if req.URL.Host != via[0].URL.Host {' \
	'if false {'

# TestMain's helper calls os.Exit again, which skips its deferred RemoveAll —
# every run leaks a directory holding a built binary;
# TestMainRemovesItsBinaryDirectory must catch it.
mutate testmain-exits-past-defer cli_e2e_test.go \
	'return m.Run()' \
	'os.Exit(m.Run()); return 0'

# audit verify reports a clean chain whatever the server said — a script gating
# on the exit code would trust a tampered journal; the TestCLI_AuditVerify_*
# broken-chain tests must catch it.
mutate audit-verify-ignores-broken-chain commands.go \
	'return res.OK, err' \
	'return true, err'

# the closed-set filter on broken_id/break_kind is bypassed — off-list server text
# reaches stdout; TestCLI_AuditVerify_FreeFormFieldsStayInsideClosedSets must catch it.
mutate audit-verify-unfiltered-fields commands.go \
	'res.BrokenID, res.BreakKind = sanitizeBreak(res.BrokenID, res.BreakKind)' \
	'_ = sanitizeBreak'

# the request_id shape check is bypassed — a server-chosen string reaches --json
# output; the same test must catch it.
mutate audit-verify-unchecked-request-id commands.go \
	'if !auditRequestID.MatchString(res.RequestID) {' \
	'if false {'

# server-supplied error text reaching the terminal (reportErr/printAPIError):
# each guard is removed on its own, then the whole control-character filter is
# turned into a no-op — errtext_test.go must go red every time.
mutate reporterr-class-unfiltered main.go \
	'safeClass(ae.ErrorClass)' 'ae.ErrorClass'
mutate reporterr-message-unfiltered main.go \
	'sanitizeText(ae.Message, maxErrTextRunes)' 'ae.Message'
mutate printapierror-message-unfiltered runner.go \
	'sanitizeText(e.Message, maxErrTextRunes)' 'e.Message'
mutate printapierror-request-id-unfiltered runner.go \
	'safeRequestID(e.RequestID)' 'e.RequestID'
mutate safeclass-accepts-anything errtext.go \
	'if string(k) == c {' 'if string(k) == c || true {'
mutate sanitize-control-filter-noop errtext.go \
	'case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r):' 'case unicode.Is(unicode.Cc, r) && false:'
mutate request-id-length-unchecked errtext.go \
	'if len(id) > maxRequestIDLen {' 'if false {'
mutate request-id-charset-lets-esc-through errtext.go \
	"r != '.' {" "r != '.' && r != 0x1b && r != 0x07 {"
mutate apierror-error-unfiltered client.go \
	'class, msg := safeClass(e.ErrorClass), sanitizeText(e.Message, maxErrTextRunes)' 'class, msg := e.ErrorClass, e.Message'
mutate sanitize-line-separators-kept errtext.go \
	'unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)' 'false'
mutate output-cell-unfiltered output.go \
	'func cell(s string) string { return sanitizeText(s, maxErrTextRunes) }' 'func cell(s string) string { return s }'
metadata_mutate TestJSONValueEscapesControlsAndPreservesUnicode 'JSON writer emitted raw control' json-control-escape-noop output.go \
	'w.Write(escapeJSONControls(buf.Bytes()))' 'w.Write(buf.Bytes())'
metadata_mutate TestJSONValueEscapesControlsAndPreservesUnicode 'JSON writer emitted raw control' json-control-escape-delete output.go \
	'w.Write(escapeJSONControls(buf.Bytes()))' 'w.Write(buf.Bytes())'
metadata_mutate TestJSONValueEscapesControlsAndPreservesUnicode 'JSON writer emitted raw control' json-c1-escape-disabled output.go \
	'unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp' 'unicode.Cf, unicode.Zl, unicode.Zp'
metadata_mutate TestJSONValueEscapesControlsAndPreservesUnicode 'JSON writer emitted raw control' json-format-escape-disabled output.go \
	'unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp' 'unicode.Cc, unicode.Zl, unicode.Zp'
metadata_mutate TestInputLinkJSONEscapesControls 'input-link emitted raw control' input-link-json-escape-noop input_link.go \
	'writeJSONValue(stdout, link)' 'json.NewEncoder(stdout).Encode(link)'
mutate debug-header-dump-unfiltered client.go \
	'sanitizeText(k, maxErrTextRunes), sanitizeText(v, maxErrTextRunes)' 'k, v'
mutate sanitize-newline-kept errtext.go \
	"r = ' '" "r = r"

# the token file open stops refusing a symlink
# at the configured path — TestResolveToken_RefusesSymlink must catch a
# symlink's target being read and returned as the bearer token.
mutate token-open-follows-symlink token_unix.go \
	'fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)' \
	'fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)'

# A credential pasted into any other slot (flag name or value, --server, --org,
# --scope-id, a positional name, a runner path) must not reach the terminal;
# TestCLI_AnySubcommandNeverEchoesPastedValue is the witness for each.
mutate flag-parse-error-printed main.go \
	'func flagParseFailed(name string, err error, stderr io.Writer) int {' \
	'func flagParseFailed(name string, err error, stderr io.Writer) int { _, _ = fmt.Fprintln(stderr, err);'
mutate subcommand-help-fails main.go \
	'func flagParseFailed(name string, err error, stderr io.Writer) int {' \
	'func flagParseFailed(name string, err error, stderr io.Writer) int { if errors.Is(err, flag.ErrHelp) { return 2 };'
mutate runner-flagset-output-not-discarded runner.go \
	'fs.SetOutput(io.Discard)' \
	'fs.SetOutput(os.Stderr)'
mutate runner-unknown-command-echoes-argument main.go \
	'fmt.Fprintln(os.Stderr, "keep runner: unknown command")' \
	'fmt.Fprintln(os.Stderr, "keep runner: unknown command", args[0])'
mutate server-url-echoed-in-https-error client.go \
	'errors.New("must use https (plain http is only allowed against a loopback host)")' \
	'fmt.Errorf("%s must use https", u.Redacted())'
mutate request-failure-detail-echoed client.go \
	'errors.New("request failed: " + requestFailureKind(err))' \
	'fmt.Errorf("request failed: %w", err)'
mutate secret-name-echoed-in-not-found commands.go \
	'return secret{}, errSecretNameNotFound()' \
	'return secret{}, &apiError{Status: http.StatusNotFound, ErrorClass: "secret_not_found", Message: "secret " + name + " not found"}'
mutate runner-server-ca-path-echoed runner.go \
	'errors.New("reading -server-ca: file could not be read")' \
	'fmt.Errorf("reading -server-ca: %w", err)'
mutate runner-policy-error-echoed runner.go \
	'reading policy file: could not be read")' \
	'reading policy file:", err)'

# (the build-request error is static, but only an unescaped org can make
# http.NewRequest fail at all, so both are switched off together)
mutate org-unescaped-and-build-error-echoed client.go \
	'"/orgs/" + url.PathEscape(c.org) + path' \
	'"/orgs/" + c.org + path' \
	'errors.New("build request: invalid URL")' \
	'fmt.Errorf("build request: %w", err)'
mutate debug-trace-prints-full-url client.go \
	'method, req.URL.Scheme, req.URL.Host, redactedHeaderDump' \
	'method, req.URL.String(), "", redactedHeaderDump'
mutate runner-enroll-request-failure-echoed runner.go \
	'"keep runner enroll-token: request failed: "+requestFailureKind(err))' \
	'"keep runner enroll-token: request failed: ", err)'
mutate runner-revoke-request-failure-echoed runner.go \
	'"keep runner revoke: request failed: "+requestFailureKind(err))' \
	'"keep runner revoke: request failed: ", err)'
mutate runner-new-request-error-echoed runner.go \
	'"keep runner enroll-token: -server is not a valid URL")' \
	'"keep runner enroll-token:", err)'

mutation_apply_only && exit "$fail"

if (cd "$root" && go test -count=1 ./$pkg/... >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
