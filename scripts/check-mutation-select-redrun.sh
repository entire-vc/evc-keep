#!/bin/sh
# Proves the selector's tests can fail. In a scratch copy of the tree
# one link of the selector or its map is cut at a time, and
# scripts/test_mutation_select.py must go red. A cut that leaves it green is
# a link nothing tests. Exits 0 only if every cut is caught and the real tree
# is green. (Not named check-*-mutations.sh: that name is a mutation check
# the selector itself would have to select.)
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
test -f "$root/go.mod" || { echo "refuse: $root does not look like the repo root" >&2; exit 2; }
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT INT TERM
export GOCACHE="$scratch/gocache"

fresh() {
	rm -rf "$scratch/t"; mkdir "$scratch/t"
	(cd "$root" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf -) | (cd "$scratch/t" && tar xf -)
	# A checkout, as in CI: the batch range and the receipts read commits and tracked files.
	# No automatic gc: a detached one would still be packing objects when the
	# next fresh() removes the tree, and rm fails on files it deletes under it.
	(cd "$scratch/t" && git init -q && git config gc.auto 0 && git config maintenance.auto false &&
		git add -A && git -c user.name=redrun -c user.email=redrun@example.invalid commit -qm tree)
}
suite() { (cd "$scratch/t" && python3 scripts/test_mutation_select.py >"$scratch/out" 2>&1); }

fresh
suite || { cat "$scratch/out" >&2; echo "FAIL: the selector tests are red on the real tree" >&2; exit 1; }
echo "baseline green"

fail=0
# cut <file> <perl substitution> <what it removes>
cut() {
	fresh
	before=$(cksum <"$scratch/t/$1")
	(cd "$scratch/t" && perl -0pi -e "$2" "$1")
	after=$(cksum <"$scratch/t/$1")
	if [ "$before" = "$after" ]; then echo "BAD MUTANT (no change): $3" >&2; fail=1; return; fi
	if suite; then echo "SURVIVED: $3" >&2; fail=1; else echo "killed:   $3"; fi
}

M=scripts/mutation-select.map
S=scripts/mutation-select.py
cut $M 's#^path internal/store/migrations/\*\* ->.*\n##m' "map: migrations link removed"
cut $M 's#(migrations/\*\* -> pkg )[^\n]*#${1}internal/obs#' "map: migrations link points at the wrong package"
cut $M 's#^path docs/\*\* -> inert\n##m; s#^path \*\*/\*\.md -> inert\n##m' "map: docs no longer inert"
cut $M 's# always\n#\n#' "map: sealer is no longer always selected"
cut $M 's#(script keep-cli\s+roots=)cmd/keep,cmd/keep-server,pkg/\.\.\.#${1}cmd/keep#' "map: keep-cli root loses cmd/keep-server"
cut $M 's#^script tenancy .*\n##m' "map: a script on disk missing from the map"
cut $S 's#r"\^internal/testutil/", ##' "selector: test helpers no longer select everything"
cut $S 's#if "testdata" in parts:#if False:#' "selector: testdata no longer belongs to its package"
cut $S 's#raise Everything\(f"unknown path \{f\}"\)#continue#' "selector: unknown path ignored"
cut $S 's#stack = \[x for r in roots for x in pkgs\[r\]\["imports"\] \+ pkgs\[r\]\["tests"\]\]#stack = [x for r in roots for x in pkgs[r]["imports"]]#' "selector: roots' test imports ignored"
cut $S 's#"all": True, "reason": f"selector error#"all": False, "reason": f"selector error#' "selector: own failure no longer says ALL"
cut $S 's#elif spec\["always"\] and changed:#elif False:#' "selector: security zone not forced in"
cut $S 's#elif spec\["always"\] and changed:#elif spec["always"]:#' "selector: security zone forced in without a package change"
cut $S 's#if p in seen or p not in pkgs:#if p in seen or p not in pkgs or len(seen) > 0 and False:#; s#stack.extend\(pkgs\[p\]\["imports"\]\)#pass#' "selector: transitive imports not followed"
cut $S 's#r"\^scripts/mutation-select\\\.\(py\|map\)\$", ##' "selector: its own source no longer selects everything"
cut $S 's#, r"\^internal/zonecheck/"##' "selector: internal/zonecheck/** no longer selects everything"
cut $S 's#"--no-renames", ##' "selector: diff listing loses the old name of a rename"
cut $S 's#out \+= "\.\*"\n            i \+= 2#out += "[^/]*"\n            i += 2#' "selector: ** no longer crosses directories"
cut $S 's#parts\.index\("testdata"\)#len(parts) - 1 - parts[::-1].index("testdata")#' "selector: testdata owner taken from the last testdata"
cut $S 's#stack\.extend\(pkgs\[p\]\["imports"\]\)#stack.extend(pkgs[p]["imports"] + pkgs[p]["tests"])#' "selector: closure follows tests of dependencies"
cut $S 's#hit = \{p for p in pkgs if p == base or p\.startswith\(base \+ "/"\)\}#hit = {p for p in pkgs if p.startswith(base)}#' "selector: dir/... matches siblings by prefix"
cut $S 's#if m\.group\(1\) in self\.scripts:#if False:#' "selector: duplicate script id accepted"
cut $S 's#"selected": \[\{"script": x, "always": False, "reason": "selector error"\} for x in every\]#"selected": []#' "selector: own failure leaves 'selected' empty"
cut $M 's#^script public-hygiene  roots=pkg/secret always#script public-hygiene  roots=pkg/secret#m' "map: public-hygiene no longer always selected"
cut $S 's#every = sorted\(known \| scripts_on_disk\(\)\)#every = sorted(known)#' "selector: error answer lists only the map's scripts (empty if unreadable)"
cut $S 's#if "120000" in meta#if "1200000" in meta#' "selector: diff listing no longer marks symlinks"
cut $S 's#        if symlinks:\n#        if False:\n#' "selector: a symlink in the diff no longer selects everything"
cut $S 's#rep = report\(files, Path\(a\.map\), links, #rep = report(files, Path(a.map), (), #' "selector: command line drops the diff's symlinks"
cut $S 's#every = sorted\(set\(m\.scripts\) \| scripts_on_disk\(\)\)#every = sorted(m.scripts)#' "selector: ALL omits a script the map forgot"
cut $S 's#return re\.compile\("\^" \+ out \+ "\$"\)#return re.compile("^" + out)#' "selector: glob no longer anchored at the end"
cut $S 's#out \+= re\.escape\(pattern\[i\]\)#out += pattern[i]#' "selector: glob literals no longer escaped"
cut $S 's#out \+= "\[\^/\]\*"\n            i \+= 1#out += ".*"\n            i += 1#' "selector: single * crosses directories"
cut $S 's#rule = next\(\(p for p in m\.paths if#rule = next((p for p in reversed(m.paths) if#' "selector: last matching rule wins"
cut $S 's# \+ imp\("XTestImports"\)##' "selector: external test imports ignored"
cut $S 's#sorted\(f for f in set\(a\.files\) if \(ROOT / f\)\.is_symlink\(\)\)#[]#' "selector: --files no longer checks symlinks"
cut $S 's# \| \{i for i in ids if i not in on_disk\}##' "selector: map script missing on disk accepted"
cut $S 's#if r\.returncode != 0:#if False:#' "selector: go list failure ignored"
G=scripts/generate-mutation-pipeline.py
cut $S 's#if not own and len\(jobs\) > 1:#if False:#' "selector: a helper several jobs share narrows"
cut $S 's#        if opaque:\n#        if False:\n#' "selector: a script path built from a variable is followed blindly"
cut $S 's#(SCRIPT_GLOB = re\.compile\(r")#${1}NEVER#' "selector: globs over scripts/ no longer followed"
cut $S 's#if not line\.lstrip\(\)\.startswith\(mark\)#if True#' "selector: commented-out script names count as use"
cut $S 's#        if key in GLOBAL_CI_KEYS:\n#        if False:\n#' "selector: workflow/variables/default changes narrow"
cut $S 's#        if key in GATING_JOBS:\n#        if False:\n#' "selector: a change to the selection jobs narrows"
cut $S 's#        if user is not None:\n#        if False:\n#' "selector: a template or anchor of post-review jobs narrows"
cut $S 's#                if side\.is_comment\(line\):\n                    continue\n##' "selector: comment lines select jobs"
cut $S 's#and line not in self\.scalar_lines#and True#' "selector: # inside a block scalar taken for a comment"
cut $S 's#raise Everything\(f"shared path \{CI_CONFIG\} \(no diff base to compare\)"\)#return set()#' "selector: CI file without a diff base narrows"
cut $S 's#            if f != TEST_CHILD_CONFIG:\n                raise Everything\(f"unknown path \{f\}"\)\n##' "selector: unknown file under .gitlab/ci/ narrows"
cut $M 's#^path plugins/mesh/\*\* -> script .*\n##m' "map: plugins/mesh no longer mapped"
cut $G 's#        return every, "selector answer is not about this commit"\n##' "generator: answer about another commit accepted"
cut $G 's#    if \(len\(set\(picked \+ rest\)\) != len\(picked \+ rest\) or set\(picked \+ rest\) != known\):#    if False:#' "generator: incomplete or repeated job lists accepted"
cut $G 's#        if not all\(isinstance\(n, str\) for n in names\):#        if False:#' "generator: a job entry without a name accepted"
cut $G 's#    if not isinstance\(commit, str\) or not SHA\.fullmatch\(commit\):#    if False:#' "generator: an answer without a head commit accepted"
cut $G 's#return every, "no selector answer"#return [], "no selector answer"#' "generator: missing answer runs nothing"
cut $G 's#out\["rules"\] = \[\{"when": "on_success"\}\]#out["rules"] = [{"when": "manual"}]#' "generator: child jobs keep a manual rule"
cut $G 's#            needs\.append\(\{"pipeline": "\$PARENT_PIPELINE_ID", "job": dep\}\)\n#            pass\n#' "generator: parent artifacts dropped"
cut $M 's#^path Dockerfile -> inert\n##m' "map: the root Dockerfile is no longer inert"
cut $M 's#^path api/openapi\.yaml -> inert\n##m' "map: api/openapi.yaml is no longer inert"
cut $M 's#^path Dockerfile -> inert#path **/Dockerfile -> inert#m' "map: every Dockerfile is inert, not only the root one"
cut $S 's#r"\^scripts/mutation-range\\\.py\$",##' "selector: the batch range no longer selects everything"
R=scripts/mutation-range.py
cut $R 's#if git\(cwd, "merge-base", "--is-ancestor", green, head\)\.returncode:#if False:#' "range: a green commit the head does not descend from narrows"
cut $R 's#if not SHA\.fullmatch\(green\):#if False:#' "range: an abbreviated commit id narrows"
cut $R 's#return None, f"no \{ARTIFACT\}"#return "HEAD", None#' "range: no green commit narrows to an empty range"
cut $R 's#    out\.unlink\(missing_ok=True\)\n    r = git#    r = git#' "range: an answer left from before survives a run that writes none"
cut $R 's#        out\.unlink\(missing_ok=True\)\n        print\("every post-review job runs: the selector failed"\)#        print("every post-review job runs: the selector failed")#' "range: a failed selector's partial answer is kept"
cut $R 's#    if r\.returncode:\n        out\.unlink#    if False:\n        out.unlink#' "range: a failed selector is not noticed"
cut $R 's#        with urllib\.request\.urlopen#        return None\n        with urllib.request.urlopen#' "range: the green commit is never fetched"
cut $R 's#headers=\{"JOB-TOKEN": token\}#headers={}#' "range: the fetch carries no job token"
cut $G 's#batch = os\.environ\.get\("KEEP_MUTATION_BATCH"\) == "true"#batch = False#' "generator: the batch variable is ignored"
cut $G 's#\[ "\$\(cat "\$f"\)" = "\{digest\}" \]#true#' "generator: a receipt skips the job whatever hash it holds"
cut $G 's#out\["script"\] = as_list\(resolved\.get\("script"\)\) \+ \[receipt_write\(name, digest\)\]#out["script"] = [receipt_write(name, digest)] + as_list(resolved.get("script"))#' "generator: the receipt is written before the job's script"
cut $G 's#\{CI_NODE_INDEX:-0\}##' "generator: shards share one receipt"
cut $G 's#inputs = reach \| fixed \| \{f for f in files if any\(d == "\." or f\.startswith\(d \+ "/"\) for d in dirs\)\}#inputs = reach | fixed#' "generator: receipt hash ignores the suites' packages"
cut $G 's#"job": ms\.resolve_job\(config, name\),#"job": None,#' "generator: receipt hash ignores the job definition"
cut $G 's#                inputs \|= \{f for f in files if regex\.match\(f\)\}#                pass#' "generator: receipt hash ignores files the map links to the packages"
cut $G 's#fixed = \{f for f in files if any\(re\.search\(p, f\) for p in ms\.ALL_PATTERNS\)\}#fixed = set()#' "generator: receipt hash ignores go.mod, go.sum and the shared paths"
cut $G 's#mutation-receipt-\{name\}-\{digest\}-#mutation-receipt-{name}-#' "generator: the receipt cache is not keyed by the hash"
cut $G 's#"none" if batch else "interruptible"#"interruptible"#' "generator: the batch child can be cancelled by a newer commit"
cut $G 's#    if digest is not None:\n        with_receipt#    if False:\n        with_receipt#' "generator: no job carries a receipt"
cut $G 's#out\["before_script"\] = \[receipt_check\(name, digest\)\] \+ as_list#out["before_script"] = as_list#' "generator: the receipt is written but never checked"
[ "$fail" = 0 ] || { echo "red run FAILED" >&2; exit 1; }
echo "red run ok: every cut is caught"
