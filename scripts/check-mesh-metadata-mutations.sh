#!/bin/sh
# Proves the guards of the metadata probe (GET .../mesh/secrets/{ref}/metadata)
# can fail (threat model 4.1, 4.3, 4.4): in a scratch copy of the tree, switch
# off one property at a time (closed answer, scalar-only SQL, no value path in
# the reader, signature, replay, journal, fail-closed, limits, registry) and
# require the named test to go red. A build
# error, a skip or an unrelated failure is not evidence. Needs a real
# PostgreSQL: KEEP_DATABASE_URL.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"
# CI runs the mutants round-robin over MUTATION_SHARD_TOTAL jobs; every shard
# also runs the unmutated baseline. A local run takes the whole list.
mutation_shard_init

fail=0
pkg=./cmd/keep-server/app
# mutate NAME FILE FROM TO TEST: replace one literal FROM with TO in FILE and
# require TEST (package $pkg) to fail with a real --- FAIL.
mutate() {
	mutation_selected || return 0
	name=$1 file=$2 from=$3 to=$4 test=$5
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! python3 - "$work/tree/$file" "$from" "$to" "${6:-}" "${7:-}" "${8:-}" <<'PY'
import sys
p, a, b, f2, a2, b2 = sys.argv[1:]
s = open(p).read()
if s.count(a) < 1:
    sys.exit(1)
open(p, 'w').write(s.replace(a, b, 1))
if f2:
    q = p.rsplit('/tree/', 1)[0] + '/tree/' + f2
    t = open(q).read()
    if t.count(a2) < 1:
        sys.exit(1)
    open(q, 'w').write(t.replace(a2, b2, 1))
PY
	then
		echo "FAIL $name: mutation did not apply, the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -count=1 -p 1 -timeout 240s -run "$test" "$pkg" >"$work/out" 2>&1); then
		echo "FAIL $name: $test stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	elif grep -Eq "$canary_re" "$work/out"; then
		# The failure itself must not print the value it caught.
		echo "FAIL $name: $test went red but its output carries a canary value"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}
# A canary value as internal/testutil/canary makes it; the detector must find
# a known one, or the check above proves nothing.
canary_re='kc[0-9a-f]{24}-v[0-9]+-secret'
if ! printf 'x kc%s-v2-secret x\n' 0123456789abcdef01234567 | grep -Eq "$canary_re"; then
	echo "FAIL canary detector: misses a known canary value"
	exit 1
fi


nl='
'
A=internal/api/mesh_metadata.go
M=internal/api/mesh.go
V=internal/builtin/mesh_metadata.go
L=TestMeshMetadataLeaksNothing
RED=TestMeshMetadataRejectsRedInputs
AUD=TestMeshMetadataAuditedAndFailClosed

# K1: the closed answer. A field added to the body, a value-bearing header,
# a cacheable answer, and a body that echoes the ref.
mutate dto-extra-field   $A 'Length    int    `json:"length"`' 'Length    int    `json:"length"`
	Ref       string `json:"ref"`' $L
mutate dto-field-renamed $A 'json:"version"`' 'json:"ver"`' $L
mutate dto-length-string $A 'json:"length"`' 'json:"length,string"`' $L
mutate answer-not-closed $A 'json.Marshal(meshMetadataAnswer{Version: meta.Version, Length: meta.Length, RequestID: requestID})' 'json.Marshal(map[string]any{"version": meta.Version, "length": meta.Length, "request_id": requestID, "ref": ref})' $L
mutate answer-no-store   $A '	w.Header().Set("Cache-Control", "no-store")
	if r.Method' '	if r.Method' $L

# K2: the reader reads two scalars, and reaches no value path.
pkg=./internal/builtin
mutate sql-reads-ciphertext $V 'SELECT version::text, octet_length(ciphertext) - 28 AS length' 'SELECT version::text, octet_length(ciphertext) - 28 AS length, ciphertext AS c' TestMeshMetadataSQLIsScalarOnly
mutate sql-select-star      $V 'SELECT version::text, octet_length(ciphertext) - 28 AS length
FROM keep_envelope' 'SELECT *
FROM keep_envelope' TestMeshMetadataSQLIsScalarOnly
mutate sql-wrapped-dek      $V 'AND secret_id = $2 AND status = '"'"'active'"'"'
ORDER BY' 'AND secret_id = $2 AND status = '"'"'active'"'"' AND wrapped_dek IS NOT NULL
ORDER BY' TestMeshMetadataSQLIsScalarOnly
mutate reader-calls-resolve $V '	var version string
	var length int
	err = m.local.pool.QueryRow' '	_, _, _ = m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
	var version string
	var length int
	err = m.local.pool.QueryRow' TestMeshMetadataReaderReachesNoValuePath $V '	"strconv"' '	"strconv"
	"github.com/entire-vc/evc-keep/pkg/provider"'
mutate reader-fingerprints  $V '	var version string
	var length int
	err = m.local.pool.QueryRow' '	_, _ = m.local.Provider(org, "", "", "").FingerprintKey(ctx)
	var version string
	var length int
	err = m.local.pool.QueryRow' TestMeshMetadataReaderReachesNoValuePath
mutate reader-writes        $V '	var version string
	var length int
	err = m.local.pool.QueryRow' '	_, _ = m.local.pool.Exec(ctx, "UPDATE keep_envelope SET status = status")
	var version string
	var length int
	err = m.local.pool.QueryRow' TestMeshMetadataReaderReachesNoValuePath
mutate helper-reads-storage $V '	n, err := strconv.ParseInt(v, 10, 64)' '	if false {
		_ = (*MeshVault)(nil).local.pool.QueryRow
	}
	n, err := strconv.ParseInt(v, 10, 64)' TestMeshMetadataHelpersTouchNoStorage
mutate version-unchecked    $V 'return err == nil && n > 0 && strconv.FormatInt(n, 10) == v' 'return err == nil && n > 0' TestMeshVersionValid
pkg=./cmd/keep-server/app
mutate length-overhead-wrong $V 'octet_length(ciphertext) - 28 AS length' 'octet_length(ciphertext) - 27 AS length' $L
mutate newest-not-latest    $V 'ORDER BY version DESC LIMIT 1`' 'ORDER BY version ASC LIMIT 1`' TestMeshMetadataNamespaceAndLifecycle
mutate status-not-active    $V "AND secret_id = \$2 AND status = 'active'" "AND secret_id = \$2 AND status <> 'erased'" TestMeshMetadataNamespaceAndLifecycle
mutate path-from-caller     $V 'path, err := meshSecretPath(workspace, ref)
	if err != nil {
		return MeshSecretMeta{}, err
	}
	var version string' 'path, err := meshSecretPath(workspace, ref)
	if err != nil {
		return MeshSecretMeta{}, err
	}
	path = "mesh/" + org + "/secrets/" + ref
	var version string' TestMeshMetadataNamespaceAndLifecycle

# K3: the signature, the nonce, the org, the shape of the request, the budget.
ACT='m.secretActorMsgs(w, r, requestID, audit.ActionMeshSecretMetadata, body, metadataActorMsgs)'
mutate actor-noop        $A "ws, org, ok := $ACT" 'ws, _ := uuid.Parse(r.Header.Get(meshHeaderWS)); org, _ := uuid.Parse(r.PathValue("org_id")); ok = true; _ = body' $RED
mutate method-not-signed $M 'msg := []byte(meshSecretSigTag + "\n" + tsRaw + "\n" + nonce + "\n" + r.Method + "\n"' 'msg := []byte(meshSecretSigTag + "\n" + tsRaw + "\n" + nonce + "\n" + "GET" + "\n"' $RED
mutate head-allowed      $A 'if r.Method != http.MethodGet {' 'if false {' $RED
mutate query-allowed     $A '|| r.URL.RawQuery != "" ||' '||' $RED
mutate body-allowed      $A 'len(body) != 0 || r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.TransferEncoding) != 0 ||' 'r.URL.RawQuery != "" || len(r.TransferEncoding) != 0 ||' $RED
mutate bad-ref-allowed   $A '|| !meshRefValid(ref) {' '{' $RED internal/builtin/mesh_vault.go 'if !meshWorkspaceRe.MatchString(workspace) || !meshSecretRefRe.MatchString(ref) || strings.Contains(ref, "..") {' 'if !meshWorkspaceRe.MatchString(workspace) {'
mutate body-limit-off    $A 'meshMetadataBodyLimit = 4096' 'meshMetadataBodyLimit = 1 << 20' $RED
mutate replay-allowed    $M 'if !fresh {' 'if !fresh && false {' TestMeshMetadataNonceIsSingleUse
mutate foreign-org-allowed $M 'perr != nil || pathOrg != owner {' 'perr != nil || (pathOrg != owner && false) {' $RED
mutate ratelimit-off     $A 'if allowed, wait := m.limit.take(bucketKey{org: org, id: ws}); !allowed {' 'if allowed, wait := true, 0; !allowed {' TestMeshMetadataIsRateLimited
mutate ratelimit-burst   $A 'meshMetadataBurst     = 10' 'meshMetadataBurst     = 11' TestMeshMetadataIsRateLimited
mutate not-found-names   $A 'm.metadataRefuse(w, r, org, ws, http.StatusNotFound, apperr.ClassNotFound, "not found", audit.ErrClassNotFound)' 'm.metadataRefuse(w, r, org, ws, http.StatusNotFound, apperr.ClassNotFound, "not found: "+ref, audit.ErrClassNotFound)' TestMeshMetadataNamespaceAndLifecycle

# K4: the journal. The success record, the refusal records, the answer that
# waits for them, the vault or the journal that is missing, the registry.
mutate audit-success-off $A 'if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretMetadata, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {' 'if err := func() error { _ = meta; return nil }(); err != nil {' $AUD
mutate audit-fp-set      $A 'meta.Fingerprint = ""' 'meta.Fingerprint = "kfp1:x:y"' $AUD
mutate audit-action-resolve $A 'audit.ActionMeshSecretMetadata, ref, meta, audit.StatusOK' 'audit.ActionMeshSecretResolve, ref, meta, audit.StatusOK' $AUD
mutate header-leaks-ref  $A '	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)' '	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Ref", ref)
	w.WriteHeader(http.StatusOK)' $L
mutate audit-refusal-off $A '	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretMetadata, "", MeshSecretMeta{}, audit.StatusFailed, ec); err != nil {' '	if err := func() error { return nil }(); err != nil {' $AUD
mutate audit-failure-open $A '	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretMetadata, "", MeshSecretMeta{}, audit.StatusFailed, ec); err != nil {
		w.Header().Del("Retry-After")' '	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretMetadata, "", MeshSecretMeta{}, audit.StatusFailed, ec); err != nil && false {
		w.Header().Del("Retry-After")' $AUD
mutate audit-success-failopen $A 'audit.StatusOK, audit.ErrClassNone); err != nil {
		writeError(w, http.StatusServiceUnavailable' 'audit.StatusOK, audit.ErrClassNone); err != nil && false {
		writeError(w, http.StatusServiceUnavailable' $AUD
mutate nonce-failure-open $M 'fresh, err := m.deps.Repo.UseNonce(r.Context(), ws, nonce)' 'fresh, err := m.deps.Repo.UseNonce(r.Context(), ws, nonce)
	if err != nil {
		fresh, err = true, nil
	}' $AUD
pkg=./internal/api
mutate journal-optional  $A 'if !ok || m.aud == nil {' 'if !ok {' TestMetadataNeedsReaderAndJournal
mutate legacy-msg-changed $M 'db: "database not reachable"' 'db: "metadata unavailable"' TestMeshLegacyActorMessagesUnchanged
mutate reader-optional   $A 'if !ok || m.aud == nil {' 'if m.aud == nil {' TestMetadataNeedsReaderAndJournal
# K3: the request id is the server's: the route does not propagate X-Request-Id.
RID=TestMetadataRequestIDIsServerGenerated
mutate rid-route-unwrapped internal/api/router.go 'withServerRequestID(logged("/orgs/{org_id}/mesh/secrets/{ref}/metadata"' '(func(h http.Handler) http.Handler { return h })(logged("/orgs/{org_id}/mesh/secrets/{ref}/metadata"' $RID
mutate rid-from-caller internal/api/middleware.go '		id := reqid.New()
		w.Header().Set(reqid.HeaderName, id)
		next.ServeHTTP(w, r.WithContext(reqid.WithContext(r.Context(), id)))
	})
}

// statusRecorder' '		id := reqid.FromHeader(r.Header.Get(reqid.HeaderName))
		w.Header().Set(reqid.HeaderName, id)
		next.ServeHTTP(w, r.WithContext(reqid.WithContext(r.Context(), id)))
	})
}

// statusRecorder' $RID
mutate rid-ctx-only-header internal/api/middleware.go '		id := reqid.New()
		w.Header().Set(reqid.HeaderName, id)
		next.ServeHTTP(w, r.WithContext(reqid.WithContext(r.Context(), id)))' '		id := reqid.New()
		w.Header().Set(reqid.HeaderName, id)
		next.ServeHTTP(w, r)' $RID
pkg=./cmd/keep-server/app
pkg=./internal/store
mutate registry-lacks-action internal/store/migrations/00049_mesh_secret_metadata_audit.sql "'mesh.token','mesh.uninstall','mesh.secret.metadata'));" "'mesh.token','mesh.uninstall'));" TestMeshSecretMetadataAuditMigration_DowngradeShown
mutate registry-down-valid   internal/store/migrations/00049_mesh_secret_metadata_audit.sql "'mesh.token','mesh.uninstall')) NOT VALID;" "'mesh.token','mesh.uninstall'));" TestMeshSecretMetadataAuditMigration_DowngradeShown
pkg=./internal/audit
mutate action-unregistered   internal/audit/record.go '	ActionMeshSecretMetadata,
	ActionMeshToken,' '	ActionMeshToken,' TestMeshSecretMetadataActionRegistered
pkg=./cmd/keep-server/app

# The unmutated tree: the metadata tests pass, and none is skipped.
if mutation_apply_only; then
	:
elif (cd "$root" && go test -count=1 -p 1 -json -run 'TestMeshMetadata|TestMetadataNeeds|TestMetadataRequestID|TestMeshLegacy|TestMeshSecretMetadata|TestMeshVersionValid' ./cmd/keep-server/app ./internal/api ./internal/builtin ./internal/store ./internal/audit >"$work/base" 2>&1) && ! grep -q -- '--- SKIP' "$work/base" && [ "$(grep -c -- '--- PASS' "$work/base")" -ge 11 ]; then
	echo "ok   baseline: metadata tests green on the real code, none skipped"
else
	echo "FAIL baseline: metadata tests red or skipped on the real code"
	echo "baseline PASS count: $(grep -c -- '--- PASS' "$work/base" || true) (need >= 11)"
	"$root/scripts/baseline-diagnostics.sh" "$root" <"$work/base" || true
	mutation_infrastructure_counts "$work/base"
	fail=1
fi
mutation_shard_finish
exit $fail
