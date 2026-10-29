#!/bin/sh
# Invoked by check-intake-service-mutations.sh locally and in CI.
# Only designated behavioral failures count; build errors and skips do not.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || test -n "${KEEP_DATABASE_URL:-}" || { echo 'FAIL metadata: PostgreSQL is required'; exit 2; }
python3 - <<'PY'
import json, os, pathlib, re, shutil, subprocess, tempfile

def catalog_diagnostic(code, out, test, marker, timed_out=False):
    # Numeric predicates only; child text may contain metadata/privacy canaries.
    print(json.dumps({
        "event": "catalog-mutant-diagnostic",
        "returncode": code,
        "exit_success": code == 0,
        "setup_failure": '[build failed]' in out or '[setup failed]' in out,
        "test_failure": '--- FAIL: '+test in out,
        "package_failure": '\"Action\":\"fail\",\"Package\":' in out,
        "witness_count": min(out.count(marker), 65535) if marker else 0,
        "skipped": '\"Action\":\"skip\"' in out,
        "timed_out": timed_out or 'panic: test timed out' in out,
        "infrastructure_failure": bool(re.search(r'panic: test timed out|database operation deadline exceeded|create scratch database failed|open admin pool on scratch database failed|connection failed \(unclassified\)', out)),
    }, sort_keys=True), flush=True)

root = pathlib.Path.cwd()
files = subprocess.check_output(['git', 'ls-files', '-co', '--exclude-standard', '-z']).decode().split('\0')
validation = 'internal/metatext/validate.go'
ref_test = 'TestCreateRefMetadataValidation'
ref_marker = 'metadata guard did not return invalid_argument'
mutations = []

def add(name, file, before, after, test=ref_test, marker=ref_marker, pkg='./internal/catalog'):
    source = (root / file).read_text()
    if source.count(before) != 1:
        raise SystemExit('FAIL '+name+': mutation target is not unique')
    mutations.append((name, file, source.replace(before, after, 1), pkg, test, marker))

# Delete the whole validator including its dependencies, preserving public constants.
source = (root / validation).read_text()
constants = re.search(r'const \(.*?\n\)', source, re.S).group()
mutations.append(('metadata-validator-noop', validation,
    'package metatext\n'+constants+'\nfunc Validate(field, value string, limit int) error { return nil }\n',
    './internal/catalog', ref_test, ref_marker))
add('metadata-utf8', validation, '!utf8.ValidString(value)', 'false')
add('metadata-limit', validation, 'utf8.RuneCountInString(value) > limit', 'false')
add('metadata-limit-off-by-one', validation, 'utf8.RuneCountInString(value) > limit', 'utf8.RuneCountInString(value) > limit+1')
add('metadata-counts-bytes', validation, 'utf8.RuneCountInString(value) > limit', 'len(value) > limit', marker='valid metadata boundary rejected')
# Cs is unreachable after valid UTF-8: malformed surrogate encodings are
# exercised by the UTF-8 mutant. Each reachable Unicode category dies alone.
for category in ['Cc', 'Cf', 'Co', 'Zl']:
    add('metadata-'+category, validation, 'unicode.'+category+', ', '')
add('metadata-Zp', validation, ', unicode.Zp)', ')')
add('metadata-Zs', validation, "unicode.Is(unicode.Zs, r) && r != ' '", 'false')
# Deliberately include the input in the closed validation error.
add('metadata-error-reflection', validation, 'invalid(field, "contains a forbidden character")', 'invalid(field, "contains a forbidden character"+value)', marker='rejected metadata escaped through the error')
for field, limit in [('name', 'NameLimit'), ('description', 'DescriptionLimit'), ('class', 'LabelLimit'), ('type', 'LabelLimit')]:
    value = {'name':'Name', 'description':'Description', 'class':'Class', 'type':'Type'}[field]
    add('metadata-field-'+field, 'internal/catalog/catalog.go',
        '{"'+field+'", in.'+value+', metatext.'+limit+'}',
        '{"'+field+'", "", metatext.'+limit+'}')

guard = 'if err := metatext.Validate("name", name, metatext.NameLimit); err != nil {'
add('metadata-store-name', 'internal/catalog/store.go', guard, guard[:-1]+' && false {', test='TestOtherMetadataWritersValidation')
for method in ['CreateOrganization', 'CreateWorkspace', 'CreateProject', 'CreateAgent', 'CreateService']:
    file = 'internal/tenancy/repo.go'
    source = (root/file).read_text()
    start = source.index('func (r *Repo) '+method+'(')
    position = source.index(guard, start)
    mutated = source[:position] + source[position:].replace(guard, guard[:-1]+' && false {', 1)
    mutations.append(('metadata-'+method, file, mutated, './internal/catalog', 'TestOtherMetadataWritersValidation', ref_marker))
add('metadata-api-utf8', 'internal/api/secrets.go', '!utf8.Valid(raw)', 'false',
    pkg='./internal/api', test='TestCreateRefMetadataInvalidUTF8', marker='API accepted invalid UTF-8 metadata')
surrogate_test = 'TestCreateRefMetadataSurrogateEscapes'
surrogate_marker = 'API accepted unpaired surrogate metadata'
add('metadata-api-surrogates-call', 'internal/api/secrets.go', '!validSurrogateEscapes(raw)', 'false', pkg='./internal/api', test=surrogate_test, marker=surrogate_marker)
file = 'internal/api/metadata_json.go'
source = (root/file).read_text()
start = source.index('func validSurrogateEscapes(')
end = source.index('// metadataWireField', start)
mutated = source[:start] + 'func validSurrogateEscapes(raw []byte) bool { return true }\n\n' + source[end:]
mutated = mutated.replace('\t"strconv"\n', '')
mutations.append(('metadata-api-surrogates-noop', file, mutated, './internal/api', surrogate_test, surrogate_marker))
for name, before, after in [
    ('high', 'n >= 0xd800 && n <= 0xdbff', 'false'),
    ('low', 'n >= 0xdc00 && n <= 0xdfff', 'false'),
    ('pair', 'err != nil || low < 0xdc00 || low > 0xdfff', 'err != nil || (low < 0xdc00 || low > 0xdfff) && false'),
]:
    add('metadata-api-surrogate-'+name, 'internal/api/metadata_json.go', before, after,
        pkg='./internal/api', test=surrogate_test, marker=surrogate_marker)

wire_test = 'TestCreateRefMetadataWireFieldErrors'
wire_marker = 'wire metadata error omitted the closed field or reason'
for kind, validator in [('utf8', 'utf8.Valid'), ('surrogate', 'validSurrogateEscapes')]:
    add('metadata-wire-field-'+kind, 'internal/api/secrets.go',
        'metadataWireField(raw, '+validator+')', '"request body"',
        pkg='./internal/api', test=wire_test, marker=wire_marker)
for field in ['name', 'description', 'class', 'type']:
    add('metadata-wire-field-'+field, 'internal/api/metadata_json.go',
        '"'+field+'"', '"other"', pkg='./internal/api', test=wire_test, marker=wire_marker)
file = 'internal/api/metadata_json.go'
source = (root/file).read_text()
start = source.index('// metadataWireField')
mutated = source[:start] + 'func metadataWireField(raw []byte, valid func([]byte) bool) string { return "request body" }\n'
for dependency in ['bytes', 'encoding/json', 'strings']:
    mutated = mutated.replace('\t"'+dependency+'"\n', '')
mutations.append(('metadata-wire-field-noop', file, mutated, './internal/api', wire_test, wire_marker))
# Last-value-wins loses only the invalid duplicate followed by a good value.
# Escaped keys and nonduplicate values retain their existing behavior.
duplicate_helper = 'func metadataWireField(raw []byte, valid func([]byte) bool) string {\n var collapsed map[string]json.RawMessage\n if err := json.Unmarshal(raw, &collapsed); err != nil { return "request body" }\n for field, value := range collapsed {\n  if valid(value) { continue }\n  for _, allowed := range []string{"name", "description", "class", "type"} {\n   if strings.EqualFold(field, allowed) { return allowed }\n  }\n }\n return "request body"\n}\n'
mutated = (source[:start] + duplicate_helper).replace('\t"bytes"\n', '')
mutations.append(('metadata-wire-field-duplicates', file, mutated, './internal/api', wire_test, wire_marker))
add('metadata-wire-field-casefold', 'internal/api/metadata_json.go', 'strings.EqualFold(field, allowed)', 'field == allowed',
    pkg='./internal/api', test=wire_test, marker=wire_marker)
name, file, mutated, pkg, test, marker = mutations[-1]
mutations[-1] = (name, file, mutated.replace('\t"strings"\n', ''), pkg, test, marker)

if os.environ.get('MUTATION_APPLY_ONLY') == '1':
    # Apply-only (scripts/mutation-helpers.sh): every anchor was found above;
    # a mutant equal to its source would prove nothing.
    bad = False
    for name, file, mutated, pkg, test, marker in mutations:
        if mutated == (root/file).read_text():
            print('FAIL '+name+': mutation did not apply — the source changed, update this script', flush=True)
            bad = True
        else:
            print('ok   '+name+': applies', flush=True)
    raise SystemExit(1 if bad else 0)

with tempfile.TemporaryDirectory(prefix='keep-metadata-') as scratch:
    tree = pathlib.Path(scratch)/'tree'
    for name in set(files):
        if not name or not (root/name).is_file(): continue
        dst = tree/name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/name, dst)
    def run(pkg, test):
        try:
            result = subprocess.run(['go', 'test', '-json', '-count=1', '-timeout=60s', '-run', '^'+test+'$', pkg],
                cwd=tree, env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        except subprocess.TimeoutExpired as exc:
            if pkg == './internal/catalog':
                # 124 denotes the wrapper timeout, not a fabricated child exit.
                partial = exc.stdout or b''
                if isinstance(partial, bytes): partial = partial.decode(errors='replace')
                catalog_diagnostic(124, partial, test, '', timed_out=True)
            raise SystemExit('FAIL metadata: subprocess timeout') from None
        return result.returncode, result.stdout.decode(errors='replace')
    for pkg, test in [('./internal/catalog', ref_test), ('./internal/catalog', 'TestOtherMetadataWritersValidation'), ('./internal/api', 'TestCreateRefMetadataInvalidUTF8'), ('./internal/api', surrogate_test), ('./internal/api', wire_test)]:
        status, out = run(pkg, test)
        if status or '"Action":"skip"' in out:
            raise SystemExit('FAIL metadata baseline: '+test)
    print('ok   metadata baseline: PostgreSQL probes pass without skips', flush=True)
    for name, file, mutated, pkg, test, marker in mutations:
        target = tree/file
        target.write_text(mutated)
        try:
            status, out = run(pkg, test)
            if pkg == './internal/catalog':
                catalog_diagnostic(status, out, test, marker)
            if (not status or '"Action":"fail","Package":' not in out or
                '--- FAIL: '+test not in out or marker not in out or
                '[build failed]' in out or '[setup failed]' in out or
                re.search(r'panic: test timed out|database operation deadline exceeded|create scratch database failed|open admin pool on scratch database failed|connection failed \(unclassified\)', out) or '"Action":"skip"' in out):
                raise SystemExit('FAIL '+name+': designated behavioral assertion was not reached')
            if name == 'metadata-wire-field-duplicates':
                events = [json.loads(line) for line in out.splitlines() if line.startswith('{')]
                failed = [e.get('Test', '') for e in events if e.get('Action') == 'fail' and e.get('Test', '').startswith(wire_test+'/')]
                if len(failed) != 8 or any(not test.endswith('#01') for test in failed):
                    raise SystemExit('FAIL '+name+': only eight escaped-key duplicate last-good witnesses must fail')
            print('ok   '+name+': designated behavioral assertion rejected mutant', flush=True)
        finally:
            target.write_text((root/file).read_text())
PY
