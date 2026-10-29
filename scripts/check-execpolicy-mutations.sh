#!/bin/sh
# Proves the exec_with_secret template guard can fail: in a scratch copy of
# the tree, switch off one check of pkg/execpolicy at a time and require
# `go test ./pkg/execpolicy/` to go red. A check whose removal leaves the
# tests green is not tested. Exits 0 only if every mutation is caught.
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
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
src=pkg/execpolicy/execpolicy.go

fail=0
# mutate NAME FROM TO: replace the first literal occurrence of FROM with TO.
mutate() {
	name=$1 from=$2 to=$3
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$src" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	run_mutant "$name"
}

# mutate_sed NAME SED-EXPR: apply a sed edit to every line of the source.
mutate_sed() {
	name=$1 expr=$2
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	sed -e "$expr" "$root/$src" >"$work/tree/$src"
	if cmp -s "$root/$src" "$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	run_mutant "$name"
}

# run_mutant NAME: the scratch tree must go red in a test, not in the build.
run_mutant() {
	name=$1
	if (cd "$work/tree" && go test -timeout 120s -count=1 ./pkg/execpolicy/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the check switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build is not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

mutate no-network-clients 'if netClients[name] {' 'if false && netClients[name] {'
mutate no-launchers       'if launchers[name] {' 'if false && launchers[name] {'
mutate no-destination     'if !allowed[strings.ToLower(h)] {' 'if false && !allowed[strings.ToLower(h)] {'
mutate no-numeric-dest    '(numericTailRe.MatchString(d.Host) && !canonicalIPv4(d.Host))' 'false'
mutate no-canonical-ip    '(numericTailRe.MatchString(d.Host) && !canonicalIPv4(d.Host))' 'numericTailRe.MatchString(d.Host)'
mutate no-hex-tail        '|0[xX][0-9a-fA-F]*)$`' ')$`'
mutate no-label-anchor    'numericTailRe = regexp.MustCompile(`(^|' 'numericTailRe = regexp.MustCompile(`(.|'
mutate no-pattern-probes  'if re.MatchString(p) {' 'if false && re.MatchString(p) {'
mutate no-address-args    'if looksLikeAddress(a, false) {' 'if false && looksLikeAddress(a, false) {'
mutate no-disguised-host   'return disguisedBareHost(a)' 'return false'
mutate bare-host-wide-old-cond 'bareHostRe.MatchString(a) && bareAddress(a, wide) {' 'bareHostRe.MatchString(a) && disguisedBareHost(a) {'
mutate bare-host-wide-flag-off 'if wide && !fileExts[strings.ToLower(a[strings.LastIndex(a, ".")+1:])] {' 'if false {'
mutate bare-host-wide-ext-ignored 'if wide && !fileExts[strings.ToLower(a[strings.LastIndex(a, ".")+1:])] {' 'if wide {'
mutate bare-host-wide-case-sensitive 'if wide && !fileExts[strings.ToLower(a[strings.LastIndex(a, ".")+1:])] {' 'if wide && !fileExts[a[strings.LastIndex(a, ".")+1:]] {'
mutate no-file-exts        'if !fileExts[strings.ToLower(a[i+1:])] {' 'if a[i+1:] != "" {'
mutate case-sensitive-ext  'fileExts[strings.ToLower(a[i+1:])]' 'fileExts[a[i+1:]]'
mutate no-stem-host        'return bareHostRe.MatchString(stem) || mixedScriptWord(stem)' 'return mixedScriptWord(stem)'
mutate no-stem-mixed       'return bareHostRe.MatchString(stem) || mixedScriptWord(stem)' 'return bareHostRe.MatchString(stem)'
mutate no-approval        'Decision{RequiresApproval: true, Destinations: ds}' 'Decision{Destinations: ds}'
mutate no-shell-syntax    'if shellRe.MatchString(a) {' 'if false && shellRe.MatchString(a) {'
mutate no-reserved-env    'if reservedEnv[e] ||' 'if false && reservedEnv[e] ||'
mutate no-value-check     '!re.MatchString(v) || unsafeValue(v, networked)' 're == nil'
mutate case-sensitive     'b := strings.ToLower(path.Base(bin))' 'b := path.Base(bin)'
mutate no-exe-suffix      'if t, ok := strings.CutSuffix(b, ext); ok && t != "" {' 'if t, ok := strings.CutSuffix(b, ext); false && ok && t != "" {'
mutate no-data-stream     'if i := strings.Index(b, ":"); i > 0 {' 'if i := strings.Index(b, ":"); false && i > 0 {'
mutate no-trailing-dots   'if t := strings.TrimRight(b, ". "); t != "" {' 'if t := strings.TrimRight(b, ". "); false && t != "" {'
mutate no-host-probes     'ps = append(append([]string(nil), probes...), hostProbes...)' 'ps = probes'
mutate no-expand-host     '(networked && hostLike(v))' 'false'
mutate narrow-allowlist   'userHost, hostPort = userHostWide, hostPortWide' 'userHost, hostPort = userHostRe, hostPortRe'
mutate wide-offline       'if looksLikeAddress(a, false) {' 'if looksLikeAddress(a, true) {'
mutate refuse-everything  'func Validate(t Template) (Decision, error) {' 'func Validate(t Template) (Decision, error) { if true { return Decision{}, ErrMalformed }'

# Unicode folding and host classes: each switched off alone must go red.
mutate fold-identity      'func foldHostish(s string) string {' 'func foldHostish(s string) string { if true { return s }'
mutate no-invisible-ban   'if strings.IndexFunc(a,' 'if false && strings.IndexFunc(a,'
mutate invisible-quotes-arg 'return Decision{}, fmt.Errorf("%w: argv[%d]", ErrInvisibleChar, i+1)' 'return Decision{}, fmt.Errorf("%w: argv[%d] %q", ErrInvisibleChar, i+1, a)'
mutate ascii-user-host    '@[\\p{L}\\p{M}\\p{N}.-]+\\.[\\p{L}\\p{M}]{2,}(:.*)?$' '@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}(:.*)?$'
mutate ascii-host-port    '^([\\p{L}\\p{M}\\p{N}.-]+\\.[\\p{L}\\p{M}]{2,}|' '^([A-Za-z0-9.-]+\\.[A-Za-z]{2,}|'
mutate ascii-user-wide    '@[\\p{L}\\p{M}\\p{N}][\\p{L}\\p{M}\\p{N}.-]*(:.*)?$' '@[A-Za-z0-9][A-Za-z0-9.-]*(:.*)?$'
mutate ascii-host-wide    '^\\[?[\\p{L}\\p{M}\\p{N}.:-]*[\\p{L}\\p{M}\\p{N}]\\]?:\\d{1,5}$' '^\\[?[A-Za-z0-9.:-]*[A-Za-z0-9]\\]?:\\d{1,5}$'
mutate ascii-host-like    '^([\\p{L}\\p{M}\\p{N}-]+\\.)+[\\p{L}\\p{M}\\p{N}-]+$' '^([A-Za-z0-9-]+\\.)+[A-Za-z0-9-]+$'
mutate_sed no-mark-class  's/\\p{M}//g'
mutate no-fold-expand     'return hostLikeRe.MatchString(v) || hostLikeRe.MatchString(foldHostish(v))' 'return hostLikeRe.MatchString(v)'
mutate no-fold-scan       'if f := foldHostish(a); f != a {' 'if f := foldHostish(a); false && f != a {'

mutate no-vs-fold         'unicode.Is(unicode.Variation_Selector, r)' 'false'
mutate no-ignorable-fold  'unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)' 'false'
mutate no-cf-fold         'if unicode.Is(unicode.Cf, r) ||' 'if false ||'
# Root label: "host." resolves as "host". Dropping it in the fold or in the
# returned hosts must each go red.
mutate no-root-dot-fold   'return rootDotRe.ReplaceAllString(s, "$1$2")' 'return s'
mutate no-root-dot-trim   'if t := strings.TrimSuffix(h, "."); t != "" {' 'if t := strings.TrimSuffix(h, "."); false && t != "" {'
mutate ascii-tld-user     '\\.[\\p{L}\\p{M}]{2,}(:.*)?$' '\\.[A-Za-z]{2,}(:.*)?$'
mutate ascii-tld-hostport '\\.[\\p{L}\\p{M}]{2,}|' '\\.[A-Za-z]{2,}|'
mutate ascii-tld-bare     ')+[\\p{L}\\p{M}]{2,}$' ')+[A-Za-z]{2,}$'
mutate_sed no-tld-mark    's/\\p{M}]{2,}/]{2,}/g'
mutate no-mark-bare-label '^([\\p{L}\\p{M}\\p{N}-]+\\.)+[\\p{L}\\p{M}]{2,}$' '^([\\p{L}\\p{N}-]+\\.)+[\\p{L}\\p{M}]{2,}$'

mutation_apply_only && exit "$fail"

# And the unmutated tree must be green, or every "red" above means nothing.
if (cd "$root" && go test -timeout 120s -count=1 ./pkg/execpolicy/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
