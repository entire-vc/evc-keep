#!/bin/sh
# Proves the Mesh extension guards can fail (threat model 4.1, 4.3): in a
# scratch copy of the tree, switch off one property of POST /mesh/install or
# POST /mesh/events at a time and require the named test to go red. A build
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
# require TEST (package ./cmd/keep-server/app) to fail with a real --- FAIL.
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

A=internal/api/mesh.go
# HMAC: the signature check, its no-op replacement, the timestamp window,
# the workspace-bound lookup, the uniform answer for an unknown workspace.
mutate hmac-check-off      $A 'if !valid {' 'if !valid && false {'                       TestMeshEventsRejectWrongSignatureAndCreateNoEffect
mutate hmac-compare-len    pkg/fingerprint/mac.go 'return hmac.Equal(tag, mac(v, msg))' 'return len(tag) == len(mac(v, msg)) && hmac.Equal(nil, nil)' TestMeshEventsRejectWrongSignatureAndCreateNoEffect
mutate hmac-noop-call      $A 'valid, err := m.deps.Vault.VerifyEvent(r.Context(), org.String(), ws.String(), append([]byte(tsRaw+"."), body...), got)' 'valid, err := true, error(nil); _, _, _, _ = ws, org, got, tsRaw' TestMeshEventsRejectWrongSignatureAndCreateNoEffect
mutate hmac-body-unbound   $A 'append([]byte(tsRaw+"."), body...)' '[]byte(tsRaw)'                  TestMeshEventsRejectWrongSignatureAndCreateNoEffect
mutate hmac-ts-unbound     $A 'append([]byte(tsRaw+"."), body...)' 'body'                            TestMeshEventsRejectWrongSignatureAndCreateNoEffect
mutate skew-window-off     $A 'if d := m.now().Sub(time.Unix(secs, 0)); d > meshMaxSkew || d < -meshMaxSkew {' 'if d := m.now().Sub(time.Unix(secs, 0)); d > 1<<62 {' TestMeshEventsRejectWrongSignatureAndCreateNoEffect
mutate skew-future-bound-off $A '|| d < -meshMaxSkew {' '{'                                          TestMeshEventsRejectWrongSignatureAndCreateNoEffect
# Signature form: Mesh sends bare lowercase hex, Keep's docs had "v1="; both
# carry one MAC. Bare hex must not skip the MAC, must not be refused (the
# defect: the old CutPrefix requirement), and the parser must not be a no-op.
mutate bare-hex-mac-skipped $A 'if !valid {' 'if !valid && strings.HasPrefix(r.Header.Get(meshHeaderSig), meshSigPrefix) {' TestMeshEventsAcceptBareHexSignature
mutate bare-hex-refused    $A '	h = strings.TrimPrefix(h, meshSigPrefix)' '	h, ok := strings.CutPrefix(h, meshSigPrefix)
	if !ok {
		return nil, false
	}' TestMeshEventsAcceptBareHexSignature
mutate sig-parse-noop      $A 'got, ok := meshEventSig(r.Header.Get(meshHeaderSig))' 'got, ok := []byte(nil), true' TestMeshEventsAcceptBareHexSignature
mutate sig-upper-open-e2e  $A "(c < 'a' || c > 'f')" "(c < 'a' || c > 'f') && (c < 'A' || c > 'F')" TestMeshEventsAcceptBareHexSignature
mutate secrets-prefix-open $A 'if !hasPrefix || derr != nil {' 'if derr != nil { _ = hasPrefix' TestMeshSecretRejectsRedInputs
pkg=./internal/api
mutate sig-len-off         $A 'if len(h) != 2*meshSigSize {' 'if false {' TestMeshEventSigShape
mutate sig-upper-open      $A "(c < 'a' || c > 'f')" "(c < 'a' || c > 'f') && (c < 'A' || c > 'F')" TestMeshEventSigShape
mutate sig-charset-off     $A "if c := h[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {" 'if c := h[i]; c == 0 && false {' TestMeshEventSigShape
mutate sig-prefix-repeat   $A '	h = strings.TrimPrefix(h, meshSigPrefix)' '	h = strings.ReplaceAll(h, meshSigPrefix, "")' TestMeshEventSigShape
pkg=./cmd/keep-server/app
mutate workspace-path-shared internal/builtin/mesh_vault.go 'return "mesh/" + workspace + "/" + kind, nil' 'return "mesh/" + kind, nil' TestMeshEventsAreBoundToTheirWorkspace
mutate keep-secret-fixed   internal/builtin/mesh_vault.go '	out := hex.EncodeToString(raw)' '	out := "abababababababababababababababababababababababababababababababab"; _ = hex.EncodeToString(raw)' TestMeshKeepSecretIsFreshRandom
mutate keep-secret-zero    internal/builtin/mesh_vault.go '	if _, err := rand.Read(raw); err != nil {' '	if _, err := rand.Read(raw[:0]); err != nil {' TestMeshKeepSecretIsFreshRandom
pkg=./internal/builtin
mutate checkpoint-events-only internal/builtin/mesh_vault.go '	for _, kind := range []string{MeshExtensionToken, MeshEventsSecret, MeshKeepSecret} {' '	for _, kind := range []string{MeshEventsSecret} {' TestMeshCheckpointRestoresEveryKind
mutate checkpoint-no-keep-secret internal/builtin/mesh_vault.go '	for _, kind := range []string{MeshExtensionToken, MeshEventsSecret, MeshKeepSecret} {' '	for _, kind := range []string{MeshExtensionToken, MeshEventsSecret} {' TestMeshCheckpointRestoresEveryKind
mutate checkpoint-unreadable-fatal internal/builtin/mesh_vault.go ' || errors.Is(err, provider.ErrDisabled) || errors.Is(err, provider.ErrUnavailable) {' ' {' TestMeshCheckpointSkipsUnreadableKinds
mutate restore-skips-token internal/builtin/mesh_vault.go '		path, err := meshPath(c.ws, kind)' '		if kind == MeshExtensionToken {
			continue
		}
		path, err := meshPath(c.ws, kind)' TestMeshCheckpointRestoresEveryKind
mutate meshpath-kind-open  internal/builtin/mesh_vault.go 'case MeshExtensionToken, MeshEventsSecret, MeshKeepSecret:' 'default:' TestMeshPathIsClosed
mutate meshpath-ws-open    internal/builtin/mesh_vault.go 'if !meshWorkspaceRe.MatchString(workspace) {' 'if false {' TestMeshPathIsClosed
pkg=./pkg/fingerprint
mutate verify-mac-unkeyed  pkg/fingerprint/mac.go 'm := hmac.New(sha256.New, key)' 'm := hmac.New(sha256.New, []byte("k")); _ = key' TestVerifyMAC
# The window digest: compared over all 32 bytes, and compared at all.
mutate match-sha256-prefix pkg/fingerprint/digest.go 'return subtle.ConstantTimeCompare(sum[:], want[:]) == 1' 'return subtle.ConstantTimeCompare(sum[:4], want[:4]) == 1' TestMatchSHA256
mutate match-sha256-noop   pkg/fingerprint/digest.go 'return subtle.ConstantTimeCompare(sum[:], want[:]) == 1' 'return subtle.ConstantTimeCompare(want[:], want[:]) == 1' TestMatchSHA256
mutate match-sha256-unbound pkg/fingerprint/digest.go 'secret.Expose(v, func(b []byte) { sum = sha256.Sum256(b) })' 'sum = want; _ = v' TestMatchSHA256
pkg=./cmd/keep-server/app
mutate audit-ok-off        $A '	m.audit(r, p, requestID, audit.StatusOK, audit.ErrClassNone)' '	_ = audit.StatusOK' TestMeshInstallSealsAndAudits
mutate audit-denied-off    $A '		m.audit(r, p, requestID, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusNotFound' '		writeError(w, http.StatusNotFound' TestMeshInstallSealsAndAudits
mutate no-store-off        $A '	w.Header().Set("Cache-Control", "no-store")' '	_ = w' TestMeshInstallSealsAndAudits
mutate token-not-sealed    $A 'err = m.deps.Vault.Put(r.Context(), org, wss, meshKindToken, string(req.ExtensionToken))' 'err = error(nil)' TestMeshInstallSealsAndAudits
mutate reinstall-restore-off $A '		_ = cp.Restore(r.Context())' '		_ = r' TestMeshFailedReinstallKeepsPreviousCredentials
mutate checkpoint-empty    internal/builtin/mesh_vault.go '		cp.prior[kind] = v' '		v.Wipe()' TestMeshFailedReinstallKeepsPreviousCredentials
mutate restore-skips-write internal/builtin/mesh_vault.go '	for kind, v := range c.prior {' '	for kind, v := range map[string]secret.Value{} {' TestMeshFailedReinstallKeepsPreviousCredentials
mutate secret-min-low      $A 'meshMinSecret   = 16' 'meshMinSecret   = 6' TestMeshInstallAuthorizationAndOwnership
mutate secret-max-off      $A 'len(req.EventsEndpointSecret) > meshMaxSecret' 'false' TestMeshInstallAuthorizationAndOwnership
mutate token-max-off       $A 'len(req.ExtensionToken) > meshMaxTokenLen' 'false' TestMeshInstallAuthorizationAndOwnership
mutate body-limit-off      $A '	r.Body = http.MaxBytesReader(w, r.Body, meshBodyLimit)' '	_ = meshBodyLimit' TestMeshInstallAuthorizationAndOwnership
mutate url-query-ok        internal/meshext/repo.go ' || u.RawQuery != ""' '' TestMeshInstallAuthorizationAndOwnership
mutate url-fragment-ok     internal/meshext/repo.go ' || u.Fragment != ""' '' TestMeshInstallAuthorizationAndOwnership
mutate url-len-off         internal/meshext/repo.go 'if len(s) > 512 {' 'if false {' TestMeshInstallAuthorizationAndOwnership
pkg=./internal/api
mutate hs-stored-digest-unchecked internal/api/mesh_handshake.go '	if !meshSHA256Valid(want) {' '	if false {' TestMeshSecretMatchTakesOnlyAFullDigest
mutate cred-format-open    internal/api/mesh.go 'func (c meshCred) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, meshCredMask) }' 'func (c meshCred) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, string(c)) }' TestMeshInstallRequestNeverPrintsCredentials
mutate cred-json-open      internal/api/mesh.go 'func (meshCred) MarshalJSON() ([]byte, error) { return []byte(`"` + meshCredMask + `"`), nil }' 'func (c meshCred) MarshalJSON() ([]byte, error) { return json.Marshal(string(c)) }' TestMeshInstallRequestNeverPrintsCredentials
mutate cred-log-open       internal/api/mesh.go 'func (meshCred) LogValue() slog.Value         { return slog.StringValue(meshCredMask) }' 'func (c meshCred) LogValue() slog.Value { return slog.StringValue(string(c)) }' TestMeshInstallRequestNeverPrintsCredentials
pkg=./cmd/keep-server/app
mutate unknown-ws-distinct $A '	if !found {
		deny()' '	if !found {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)' TestMeshEventsRejectWrongSignatureAndCreateNoEffect
mutate event-ws-mismatch   internal/meshext/hierarchy.go 'w.WorkspaceID != ws.String() ||' ''                  TestMeshEventsRejectMalformedSignedEvents
mutate event-type-open     internal/meshext/hierarchy.go '|| !EventTypes[w.Type]' ''                                  TestMeshEventsRejectMalformedSignedEvents
# Replay: the event id must be the dedup key.
mutate replay-dedup-off    internal/meshext/hierarchy.go 'VALUES ($1, $2, $3)
ON CONFLICT' 'VALUES ($1, $2 || gen_random_uuid()::text, $3)
ON CONFLICT' TestMeshEventReplayDoesNotDuplicateEffect
# Install: admin only, workspace ownership, input validation, one-time secret.
mutate install-admin-off   $A '	if !admin {
		m.audit' '	if !admin && false {
		m.audit'                                                                                      TestMeshInstallAuthorizationAndOwnership
# Ownership is enforced twice (pre-check, then the upsert's WHERE); each layer alone is covered by the other, so the mutants remove both and then each alone must still hold.
mutate takeover-both-off   internal/meshext/repo.go ' WHERE mesh_installations.org_id = EXCLUDED.org_id' '' TestMeshInstallAuthorizationAndOwnership $A 'found && owner != p.OrgID' 'found && owner != p.OrgID && false'
mutate mesh-url-open       internal/meshext/repo.go 'case "https":
		return true' 'case "https", "ftp":
		return true' TestMeshInstallAuthorizationAndOwnership
mutate url-creds-allowed   internal/meshext/repo.go 'u.Host == "" || u.User != nil ||' 'u.Host == "" ||' TestMeshInstallAuthorizationAndOwnership
mutate unknown-fields-ok   $A '	dec.DisallowUnknownFields()
	if err := dec.Decode(&req)' '	if err := dec.Decode(&req)'                                           TestMeshInstallAuthorizationAndOwnership
mutate vault-put-skips     internal/builtin/mesh_vault.go '	b := []byte(value)' '	if kind == MeshEventsSecret {
		return nil
	}
	b := []byte(value)' TestMeshInstallAuthorizationAndOwnership
mutate wrong-secret-kind   internal/builtin/mesh_vault.go 'meshPath(workspace, MeshEventsSecret)' 'meshPath(workspace, MeshKeepSecret)' TestMeshEventReplayDoesNotDuplicateEffect
# Leaks: each plants a leak on a different surface; the canary test must see it.
mutate leak-token-header   $A '	w.Header().Set("Cache-Control", "no-store")' '	w.Header().Set("X-Debug", string(req.ExtensionToken))' TestMeshCredentialsNeverLeak
mutate leak-secret-error   $A 'writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid mesh install fields", requestID)' 'writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid mesh install fields "+string(req.EventsEndpointSecret), requestID)' TestMeshCredentialsNeverLeak
mutate leak-keep-secret-hdr $A '	w.Header().Set("Cache-Control", "no-store")' '	w.Header().Set("X-Keep", keepSecret)'     TestMeshCredentialsNeverLeak
mutate leak-event-body-log $A '	ev, err := meshext.ParseEvent(body, ws, m.now(), r.Header.Get(meshHeaderEvent), r.Header.Get(meshHeaderDelivery))' '	w.Header().Set("X-Echo", string(body))
	ev, err := meshext.ParseEvent(body, ws, m.now(), r.Header.Get(meshHeaderEvent), r.Header.Get(meshHeaderDelivery))'                                                                                  TestMeshCredentialsNeverLeak
mutate manifest-event-drift mesh-extension.json '"task.gate.decided"]' '"task.gate.decided", "extra.event"]' TestMeshManifestMatchesServer
# Rotation rights sit only in the keep-rotator manifest (RT); keep holds none.
RT=mesh-extension.keep-rotator.json
mutate keep-gets-rotate     mesh-extension.json '"agent_keys:read", ' '"agent_keys:read", "agent_key:rotate", ' TestMeshManifestsSplitRotationRights
mutate keep-gets-self-rotate mesh-extension.json '"agent_keys:read", ' '"agent_keys:read", "ext_token:self_rotate", ' TestMeshManifestsSplitRotationRights
mutate keep-gets-keys-write mesh-extension.json '"agent_keys:read", ' '"agent_keys:read", "agent_keys:write", ' TestMeshManifestsSplitRotationRights
mutate rotator-read-dropped $RT '"agent_keys:read", ' '' TestMeshRotatorManifestIsNarrow
mutate rotator-rotate-dropped $RT '"agent_key:rotate", ' '' TestMeshManifestsSplitRotationRights
mutate rotator-self-rotate-dropped $RT ', "ext_token:self_rotate"' '' TestMeshManifestsSplitRotationRights
mutate rotator-extra-right  $RT '"ext_token:self_rotate"]' '"ext_token:self_rotate", "tasks:write"]' TestMeshRotatorManifestIsNarrow
mutate rotator-events       $RT '"secrets": []' '"events": ["task.created"], "secrets": []' TestMeshRotatorManifestIsNarrow
mutate rotator-ui           $RT '"secrets": []' '"ui": ["sidebar.item"], "secrets": []' TestMeshRotatorManifestIsNarrow
mutate rotator-network      $RT '"secrets": []' '"network": { "allowed_domains": ["{settings.keep_url}"] }, "secrets": []' TestMeshRotatorManifestIsNarrow
mutate rotator-token-path   $RT '"events_path": "/mesh/events"' '"events_path": "/mesh/events", "token_path": "/mesh/token"' TestMeshRotatorManifestIsNarrow
mutate rotator-schema-unchecked cmd/keep-server/app/mesh_manifest_test.go 'var meshManifestPaths = []string{keepManifestPath, rotatorManifestPath}' 'var meshManifestPaths = []string{keepManifestPath}' TestMeshManifestsSplitRotationRights
mutate rotator-api-capability-unknown $RT '"agent_keys:read"' '"agent_keys:bogus"' TestMeshManifestValidAgainstMeshSchema
mutate manifest-description-dropped mesh-extension.json '"description": "Store and distribute secrets to people and agents; values never enter model context.",' '' TestMeshManifestValidAgainstMeshSchema
mutate manifest-api-capability-unknown mesh-extension.json '"agent_keys:read"' '"agent_keys:bogus"' TestMeshManifestValidAgainstMeshSchema
mutate manifest-sidebar-title mesh-extension.json '"title": "Keep"' '"title": "Secrets"' TestMeshManifestMatchesServer
mutate manifest-sidebar-path mesh-extension.json '"path": "/mesh/ui/secrets"' '"path": "/mesh/ui/keep"' TestMeshManifestMatchesServer
mutate manifest-project-level mesh-extension.json '"project": false' '"project": true' TestMeshManifestMatchesServer
mutate manifest-no-token-path mesh-extension.json '"token_path": "/mesh/token",' '' TestMeshManifestMatchesServer
# Install over the plain listener, and install without the per-workspace lock.
mutate install-plain-ok    internal/api/router.go 'chain(requireTLS, authenticate(ir, logger, false))' 'chain(authenticate(ir, logger, false))' TestMeshInstallNotServedOverPlainHTTP
mutate install-lock-noop   $A 'unlock, err := m.deps.Repo.LockWorkspace(r.Context(), ws)' 'unlock, err := func() {}, error(nil)' TestMeshInstallWaitsForWorkspaceLock
mutate install-lock-late   $A '	defer unlock()
' '	defer unlock()
	unlock()
' TestMeshInstallWaitsForWorkspaceLock
mutate lock-pool-unbounded internal/meshext/repo.go 'make(chan struct{}, n)' 'make(chan struct{}, 1000)' TestMeshInstallsDoNotExhaustSmallPool
mutate routes-always-on    cmd/keep-server/app/main.go 'if !cfg.MeshExtension {' 'if false {' TestMeshExtensionOffServesNoRoutes

# Federation (K5.2): the context-token verifier and the session route. Verifier
# mutants run against ./internal/meshext, the rest against ./cmd/keep-server/app.
V=internal/meshext/jwks.go
F=internal/meshext/federation.go
pkg=./internal/meshext
V1=TestVerifyRefusesBadContexts
mutate fed-sig-off         $V 'if !ecdsa.Verify(key, digest[:], r, s) {' 'if !ecdsa.Verify(key, digest[:], r, s) && false {' $V1
mutate fed-sig-noop        $V 'if !ecdsa.Verify(key, digest[:], r, s) {' 'if _, _, _, _ = key, digest, r, s; false {'          $V1
mutate fed-exp-off         $V '!exp.After(now) ||' 'false ||'                                                           $V1
mutate fed-lifetime-off    $V 'exp.Sub(iat) > maxLifetime ||' 'false ||'                                                $V1
mutate fed-alg-off         $V 'head.Alg != "ES256" ||' 'false ||'                                                       $V1
mutate fed-iss-off         $V 'strings.TrimRight(c.Iss, "/") != strings.TrimRight(meshURL, "/") ||' 'false ||'         $V1
mutate fed-aud-off         $V '|| c.Aud[0] != v.aud {' '|| false {'                                                     $V1
mutate fed-ws-off          $V 'ws != workspace ||' 'false ||'                                                           TestVerifyWorkspaceMustMatchSignedClaim
mutate fed-reload-floor    $V 'if !st.lastAttempt.IsZero() && now.Sub(st.lastAttempt) < jwksMinReload {' 'if false {' TestVerifyReloadsKeysOnUnknownKidButNotOnEveryRequest
mutate fed-redirect-follow $V 'CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },' '' TestVerifyDoesNotFollowRedirectsOffTheInstalledMesh
mutate fed-leak-error      $V '	if !ecdsa.Verify(key, digest[:], r, s) {
		return ContextClaims{}, ErrInvalidContext' '	if !ecdsa.Verify(key, digest[:], r, s) {
		return ContextClaims{}, errors.New(ErrInvalidContext.Error() + raw)' TestVerifyNeverLeaksTokenText
V2=TestVerifyRefusesMoreBadClaims
mutate fed-nbf-off         $V '(c.Nbf != nil &&' '(false &&'                                                            $V2
mutate fed-iat-future-off  $V 'iat.After(now.Add(clockSkew)) ||' 'false ||'                                             $V2
mutate fed-iat-required    $V 'c.Exp == nil || c.Iat == nil {' 'c.Exp == nil {'                                         $V2
mutate fed-aud-multi       $V 'len(c.Aud) != 1 ||' 'len(c.Aud) < 1 ||'                                                  $V2
mutate fed-email-off       $V 'c.Email == "" ||' 'false ||'                                                             $V2
mutate fed-sub-colon       $V 'strings.ContainsAny(c.Sub, ": \t\r\n") ||' 'false ||'                                    $V2
V3=TestVerifyIgnoresUnsuitableKeysAndBadKeySets
mutate fed-jwks-alg-off    $V '(k.Alg != "" && k.Alg != "ES256")' 'false'                                               $V3
mutate fed-jwks-crv-off    $V 'k.Crv != "P-256" ||' 'false ||'                                                          $V3
mutate fed-jwks-use-off    $V '(k.Use != "" && k.Use != "sig")' 'false'                                                 $V3
mutate fed-jwks-size-off   $V 'len(body) > jwksMaxBody' 'false'                                                         $V3
mutate fed-jwks-dup-kid    $V 'if _, dup := set.keys[k.Kid]; dup {' 'if false {'                                       $V3
V4=TestVerifyCacheTTLRetiresKeysAndStaleSetHasACeiling
mutate fed-ttl-off         $V 'now.Sub(st.set.fetchedAt) < jwksTTL' 'true'                                              $V4
mutate fed-stale-off       $V 'if st.set != nil && now.Sub(st.set.fetchedAt) < jwksStaleMax {' 'if false {'             $V4
mutate fed-stale-forever   $V 'now.Sub(st.set.fetchedAt) < jwksStaleMax {' 'now.Sub(st.set.fetchedAt) < 1000*time.Hour {' $V4
V5=TestVerifyFailedFetchesAreRateLimitedAndMeshesAreIndependent
mutate fed-no-negative-cache $V '	st.lastAttempt = now
' ''                                                                                                                      $V5
mutate fed-shared-lock     $V 'st := v.meshState(base)' 'st := v.meshState("")'                                         $V5
V6=TestVerifyDefaultClientNeverDialsPrivateOrLoopbackForHTTPS
mutate fed-ssrf-off        $V '(blockedAddr(ip) && (!allowLoopback || !ip.IsLoopback()))' 'false'                       $V6
mutate fed-ssrf-https-dev  $V 'if strings.HasPrefix(base, "http://") {' 'if true {'                                     $V6
mutate fed-ssrf-cgnat      $V 'ip4[0] == 100 &&' 'ip4[0] == 101 &&'                                                     $V6
mutate fed-ssrf-private    $V 'ip.IsPrivate() ||' 'false ||'                                                            $V6
pkg=./cmd/keep-server/app
S=TestMeshSessionRefusesBadContextsWithNoEffect
mutate fed-verify-noop     $F 'claims, err := f.ver.Verify(ctx, meshURL, ws, tok)' 'claims, err := ContextClaims{Subject: "x", Email: "x@example.test", Workspace: ws}, error(nil)' $S
mutate fed-email-link      $F 'pg.Code == "23505"' 'pg.Code == "00000"'                                                 TestMeshSessionEmailNeverLinksAnExistingUser
mutate fed-removed-ok      $F 'if status != "active" {' 'if false {'                                                    TestMeshSessionRemovedUserRefused
mutate fed-session-plain   internal/api/router.go 'requireTLS(http.HandlerFunc(mr.handleSession))' 'http.HandlerFunc(mr.handleSession)' TestMeshSessionNotServedOverPlainHTTPAndWhenMeshOff
mutate fed-csrf-origin-off $A 'if !sameOrigin(r) || !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {' 'if false {' TestMeshSessionRefusesCrossSiteAndNonJSONPosts
mutate fed-csrf-ctype-off  $A '|| !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {' '|| false {' TestMeshSessionRefusesCrossSiteAndNonJSONPosts
mutate fed-cookie-js       $A 'HttpOnly: true, Secure: true,' 'HttpOnly: false, Secure: true,'                          TestMeshSessionOpensForValidContextAndMapsUser
mutate fed-leak-resp       $A '"authentication failed", requestID)
		return
	case err != nil:' '"authentication failed "+string(req.Ctx), requestID)
		return
	case err != nil:'                                                                                                     TestMeshSessionNeverLeaksContextToken
pkg=./cmd/keep-server/app

# K5.9, the Mesh secrets API (PUT and resolve by a workspace). Each guard is
# switched off alone; a double barrier (api and vault) is switched off in both.
T=TestMeshSecretRejectsRedInputs
mutate secret-sig-off      $A '	if err != nil || !valid {' '	if (err != nil || !valid) && false {'      $T
mutate secret-verify-noop  $A '	valid, err := m.deps.Vault.VerifyEvent(r.Context(), owner.String(), ws.String(), msg, got)' '	valid, err := true, error(nil); _, _ = msg, got' $T
mutate secret-skew-off     $A 'if d := m.now().Sub(time.Unix(secs, 0)); d > meshMaxSkew || d < -meshMaxSkew {
		return deny()' 'if d := m.now().Sub(time.Unix(secs, 0)); d > 1<<62 {
		return deny()' $T
mutate secret-org-unbound  $A 'perr != nil || pathOrg != owner {' 'false && (perr != nil || pathOrg != owner) {' $T
mutate secret-tls-off-put  internal/api/router.go 'requireTLS(http.HandlerFunc(mr.handlePutSecret))' 'http.HandlerFunc(mr.handlePutSecret)' TestMeshSecretRoutesGated
mutate secret-tls-off-resolve internal/api/router.go 'requireTLS(http.HandlerFunc(mr.handleResolveSecret))' 'http.HandlerFunc(mr.handleResolveSecret)' TestMeshSecretRoutesGated
mutate secret-ns-shared    internal/builtin/mesh_vault.go 'return "mesh/" + workspace + "/secrets/" + ref, nil' 'return "mesh/secrets/" + ref, nil' TestMeshSecretNamespaceIsolation
mutate secret-ns-root      internal/builtin/mesh_vault.go 'return "mesh/" + workspace + "/secrets/" + ref, nil' 'return "mesh/" + workspace + "/" + ref, nil' TestMeshSecretNamespaceIsolation
mutate secret-ref-open     internal/builtin/mesh_vault.go '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' '^.*$' TestMeshSecretRefIsClosed internal/api/mesh.go '		default:
			return false' '		default:'
mutate secret-dotdot-open  internal/builtin/mesh_vault.go ' || strings.Contains(ref, "..") {' ' || (strings.Contains(ref, "..") && false) {' TestMeshSecretRefIsClosed internal/api/mesh.go 'strings.Contains(ref, "..") {' 'false {'
mutate secret-notfound-503 internal/builtin/mesh_vault.go 'if errors.Is(err, provider.ErrNotFound) || errors.Is(err, provider.ErrDisabled) {
		return nil, MeshSecretMeta{}, ErrMeshSecretNotFound' 'if errors.Is(err, provider.ErrDisabled) {
		return nil, MeshSecretMeta{}, ErrMeshSecretNotFound' TestMeshSecretNamespaceIsolation
mutate secret-no-store-off $A '	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)' '	w.Header().Set("Cache-Control", "max-age=60")
	w.WriteHeader(http.StatusOK)' TestMeshSecretValueOnlyInResolveBody
mutate secret-ctype-off    $A '	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)' '	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)' TestMeshSecretValueOnlyInResolveBody
mutate secret-audit-put-off $A 'if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretPut, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {' '_ = meta
	if false {' TestMeshSecretAudited
mutate secret-audit-resolve-off $A 'if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretResolve, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {' '_ = meta
	if false {' TestMeshSecretAudited
mutate secret-audit-refusal-off $A '	if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil {' '	_, _ = name, ec
	if aerr := error(nil); aerr != nil {' TestMeshSecretAudited
mutate secret-refusal-audit-ignored $A 'if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil {' 'if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil && false {' TestMeshSecretRefusalNeedsItsAuditRecord
mutate secret-refusal-audit-ignored-notfound $A 'if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil {' 'if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil && !errors.Is(err, ErrMeshSecretNotFound) {' TestMeshSecretRefusalNeedsItsAuditRecord
mutate secret-refusal-audit-ignored-invalid $A 'if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil {' 'if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil && !errors.Is(err, ErrMeshSecretInvalid) {' TestMeshSecretRefusalNeedsItsAuditRecord
mutate secret-throttle-audit-ignored $A '		if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretResolve, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPolicyDenied); err != nil {' '		if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretResolve, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPolicyDenied); err != nil && false {' TestMeshSecretRefusalNeedsItsAuditRecord
mutate secret-audit-no-fp  $A 'Result:    audit.Result{Status: status, Fingerprint: meta.Fingerprint, Length: meta.Length, ErrorClass: class},' 'Result:    audit.Result{Status: status, Length: meta.Length, ErrorClass: class},' TestMeshSecretAudited
mutate secret-ratelimit-off $A 'm.resolve.take(bucketKey{org: org, id: ws}); !allowed {' 'm.resolve.take(bucketKey{org: org, id: ws}); !allowed && false {' TestMeshSecretResolveIsRateLimited
mutate secret-foreign-org-audit-ignored $A '	if pathOrg, perr := uuid.Parse(r.PathValue("org_id")); perr != nil || pathOrg != owner {
		if err := m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPermissionDenied); err != nil {' '	if pathOrg, perr := uuid.Parse(r.PathValue("org_id")); perr != nil || pathOrg != owner {
		if err := m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPermissionDenied); err != nil && false {' TestMeshSecretRefusalNeedsItsAuditRecord
mutate secret-foreign-org-unaudited $A '	if pathOrg, perr := uuid.Parse(r.PathValue("org_id")); perr != nil || pathOrg != owner {
		if err := m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPermissionDenied); err != nil {' '	if pathOrg, perr := uuid.Parse(r.PathValue("org_id")); perr != nil || pathOrg != owner {
		_, _ = owner, action
		if err := error(nil); err != nil {' TestMeshSecretAudited
mutate secret-ratelimit-unaudited $A '		if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretResolve, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPolicyDenied); err != nil {' '		if err := error(nil); err != nil {' TestMeshSecretResolveIsRateLimited
mutate secret-ratelimit-shared $A 'm.resolve.take(bucketKey{org: org, id: ws})' 'm.resolve.take(bucketKey{org: org})' TestMeshSecretResolveIsRateLimited
mutate secret-nonce-failure-unaudited $A '		_ = m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassInternal)' '		_ = r' TestMeshSecretNonceStoreFailureFailsClosed
mutate secret-replay-unaudited $A '	if !fresh {
		if err := m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPermissionDenied); err != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
			return uuid.Nil, uuid.Nil, false
		}
		return deny()
	}' '	if !fresh {
		return deny()
	}' TestMeshSecretSignedRequestIsSingleUse
mutate secret-resolve-body-ok $A 'if len(body) != 0 {' 'if false {' TestMeshSecretResolveBodyIsClosed
mutate secret-body-trailing-ok $A 'err != nil || dec.Decode(&struct{}{}) != io.EOF || req.Value == ""' 'err != nil || req.Value == ""' TestMeshSecretPutBodyIsClosed
mutate secret-empty-value-ok $A '|| req.Value == "" ||' '||' TestMeshSecretPutBodyIsClosed internal/builtin/mesh_vault.go 'if err != nil || value == "" {' 'if err != nil {'
mutate secret-value-max-off $A '|| len(req.Value) > meshMaxSecretValue ||' '||' TestMeshSecretPutBodyIsClosed internal/api/mesh.go 'meshBodyLimit   = 64 << 10' 'meshBodyLimit   = 64 << 30'
mutate secret-leak-into-put-answer $A 'Fingerprint: meta.Fingerprint})
}

// handleResolveSecret' 'Fingerprint: string(req.Value)})
}

// handleResolveSecret' TestMeshSecretValueOnlyInResolveBody
mutate secret-leak-into-audit $A 'audit.ActionMeshSecretPut, ref, meta, audit.StatusOK' 'audit.ActionMeshSecretPut, string(req.Value), meta, audit.StatusOK' TestMeshSecretValueOnlyInResolveBody
mutate secret-put-pending-off $A 'audit.ActionMeshSecretPut, ref, MeshSecretMeta{}, audit.StatusPending, audit.ErrClassNone); err != nil {' 'audit.ActionMeshSecretPut, ref, MeshSecretMeta{}, audit.StatusPending, audit.ErrClassNone); err != nil && false {' TestMeshSecretNoAnswerWithoutAuditRecord
mutate secret-put-final-audit-ignored $A 'if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretPut, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {' '_ = m.auditSecret(r, org, ws, audit.ActionMeshSecretPut, ref, meta, audit.StatusOK, audit.ErrClassNone)
	if false {' TestMeshSecretNoAnswerWithoutAuditRecord
mutate secret-json-quote-raw internal/builtin/mesh_vault.go "case c == '\"' || c == '\\\\':" "case c == '\\\\':" TestMeshSecretResolveRoundTripsAnyValue
mutate secret-disabled-served internal/builtin/mesh_vault.go 'if errors.Is(err, provider.ErrNotFound) || errors.Is(err, provider.ErrDisabled) {
		return nil, MeshSecretMeta{}, ErrMeshSecretNotFound' 'if errors.Is(err, provider.ErrNotFound) {
		return nil, MeshSecretMeta{}, ErrMeshSecretNotFound' TestMeshSecretDisabledVersionIsNotFound
# Single-use nonce: spending it, signing it, its shape, its uniqueness, its
# retention, and refusing when the store cannot record it.
R=internal/meshext/repo.go
N='fresh, err := m.deps.Repo.UseNonce(r.Context(), ws, nonce)'
mutate nonce-spend-off $A "$N" 'fresh, err := true, error(nil); _ = nonce' TestMeshSecretSignedRequestIsSingleUse
mutate nonce-insert-ignored $R 'return false, fmt.Errorf("meshext: record nonce: %w", err)
	}
	return tag.RowsAffected() == 1, nil' 'return false, fmt.Errorf("meshext: record nonce: %w", err)
	}
	_ = tag
	return true, nil' TestMeshSecretSignedRequestIsSingleUse
mutate nonce-not-signed $A 'tsRaw + "\n" + nonce + "\n" + r.Method' 'tsRaw + "\n" + r.Method' TestMeshSecretRejectsRedInputs
mutate nonce-shape-off $A 'if !meshNonceValid(nonce) {' 'if false && !meshNonceValid(nonce) {' TestMeshSecretNonceShapeIsClosed
mutate nonce-unique-weakened internal/store/migrations/00037_mesh_secret_nonces.sql 'PRIMARY KEY (workspace_id, nonce)' 'PRIMARY KEY (workspace_id, nonce, seen_at)' TestMeshSecretSignedRequestIsSingleUse $R 'ON CONFLICT (workspace_id, nonce) DO NOTHING' 'ON CONFLICT DO NOTHING'
mutate nonce-not-per-workspace internal/store/migrations/00037_mesh_secret_nonces.sql 'PRIMARY KEY (workspace_id, nonce)' 'PRIMARY KEY (nonce)' TestMeshSecretNonceIsPerWorkspace $R 'ON CONFLICT (workspace_id, nonce) DO NOTHING' 'ON CONFLICT (nonce) DO NOTHING'
mutate nonce-spent-before-signature $A 'valid, err := m.deps.Vault.VerifyEvent(r.Context(), owner.String(), ws.String(), msg, got)' '_, _ = m.deps.Repo.UseNonce(r.Context(), ws, nonce)
	valid, err := m.deps.Vault.VerifyEvent(r.Context(), owner.String(), ws.String(), msg, got)' TestMeshSecretUnsignedTrafficSpendsNoNonce
mutate nonce-retention-too-short $R 'const nonceRetention = 15 * time.Minute' 'const nonceRetention = 5 * time.Minute' TestMeshSecretNoncesArePruned
mutate nonce-never-pruned $R 'DELETE FROM mesh_secret_nonces WHERE seen_at <' 'DELETE FROM mesh_secret_nonces WHERE false AND seen_at <' TestMeshSecretNoncesArePruned
mutate nonce-store-failure-open $A "$N" "$N
	if err != nil {
		fresh, err = true, nil
	}" TestMeshSecretNonceStoreFailureFailsClosed
pkg=./internal/store
mutate secret-audit-registry-short internal/store/migrations/00036_mesh_secret_audit.sql "'secret.rotate','mesh.secret.put','mesh.secret.resolve'));" "'secret.rotate','mesh.secret.put'));" TestMeshSecretAuditMigration_DowngradeShown
mutate secret-audit-down-valid     internal/store/migrations/00036_mesh_secret_audit.sql "'secret.rotate')) NOT VALID;" "'secret.rotate'));" TestMeshSecretAuditMigration_DowngradeShown
mutate nonce-down-keeps-table      internal/store/migrations/00037_mesh_secret_nonces.sql 'DROP TABLE mesh_secret_nonces;' 'SELECT 1;' TestMeshSecretNoncesMigration_DowngradeShown
mutate nonce-shape-check-off       internal/store/migrations/00037_mesh_secret_nonces.sql "CHECK (nonce ~ '^[A-Za-z0-9_-]{16,64}\$')" "CHECK (true)" TestMeshSecretNoncesMigration_DowngradeShown
# Authenticated smoke over real TLS (TestMeshExtensionSmoke): the secrets API guards.
pkg=./cmd/keep-server/app
smoke=TestMeshExtensionSmoke
nl='
'
mutate put-no-store      $A "w.Header().Set(\"Cache-Control\", \"no-store\")${nl}	writeJSON(w, http.StatusOK, MeshSecretPutResult" "_ = w${nl}	writeJSON(w, http.StatusOK, MeshSecretPutResult" $smoke
mutate resolve-no-store  $A "w.Header().Set(\"Cache-Control\", \"no-store\")${nl}	w.Header().Set(\"Content-Type\"" "w.Header().Set(\"Content-Type\"" $smoke
mutate signature-noop    $A 'valid, err := m.deps.Vault.VerifyEvent(r.Context(), owner.String(), ws.String(), msg, got)' 'valid, err := true, error(nil); _, _, _ = owner, msg, got' $smoke
mutate nonce-replay-off  $A 'if !fresh {' 'if !fresh && false {' $smoke
mutate org-check-off     $A 'perr != nil || pathOrg != owner {' 'perr != nil || (pathOrg != owner && false) {' $smoke
mutate namespace-off     internal/builtin/mesh_vault.go 'return "mesh/" + workspace + "/secrets/" + ref, nil' 'return "mesh/x/secrets/" + ref, nil' $smoke
mutate put-value-header  $A "w.Header().Set(\"Cache-Control\", \"no-store\")${nl}	writeJSON(w, http.StatusOK, MeshSecretPutResult" "w.Header().Set(\"Cache-Control\", \"no-store\"); w.Header().Set(\"X-Dbg\", string(req.Value))${nl}	writeJSON(w, http.StatusOK, MeshSecretPutResult" $smoke
mutate resolve-audit-off $A 'if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretResolve, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {' 'if err := func() error { _ = meta; return nil }(); err != nil {' $smoke
mutate audit-length-off  $A 'Fingerprint: meta.Fingerprint, Length: meta.Length, ErrorClass: class}' 'Fingerprint: meta.Fingerprint, Length: 0, ErrorClass: class}' $smoke
pkg=./cmd/keep-server/app

# Mesh's install handshake (POST /mesh/install without Authorization) and the
# admin's install window: every guard switched off, and each check replaced by
# a no-op whose inputs are discarded.
pkg=./cmd/keep-server/app
# The handshake lives in its own file, so the first match of a pattern
# shared with handleInstall or handleEvents never lands here.
HS=internal/api/mesh_handshake.go
R=internal/meshext/repo.go
H=TestMeshHandshakeOutcomes
mutate hs-signature-off     $HS 'if !m.deps.Vault.VerifyInstall(signingSecret, append([]byte(tsRaw+"."), body...), got) {' 'if false && !m.deps.Vault.VerifyInstall(signingSecret, append([]byte(tsRaw+"."), body...), got) {' $H
mutate hs-signature-noop    $HS 'if !m.deps.Vault.VerifyInstall(signingSecret, append([]byte(tsRaw+"."), body...), got) {' '_, _ = tsRaw, got
	if false {' $H
mutate hs-verify-unkeyed    internal/builtin/mesh_vault.go '	return fingerprint.VerifyMAC(v, msg, tag)
}

// MatchInstallSecret' '	return len(tag) == 32 || fingerprint.VerifyMAC(v, msg, tag)
}

// MatchInstallSecret' $H
mutate hs-body-unbound      $HS 'VerifyInstall(signingSecret, append([]byte(tsRaw+"."), body...), got)' 'VerifyInstall(signingSecret, []byte(tsRaw+"."), got)' $H
# A foreign extension_id (keep-rotator shares install_path) is refused before
# the per-workspace budget: checking it after install.take locks keep out.
mutate hs-extension-after-budget $HS 'if err != nil || req.ExtensionID != meshext.ExtensionID ||' 'if err != nil ||' TestMeshHandshakeGuards $HS '	signingSecret := string(req.SigningSecret)' '	if req.ExtensionID != meshext.ExtensionID {
		deny()
		return
	}
	signingSecret := string(req.SigningSecret)'
mutate hs-digest-off        $HS 'if !live || !m.meshSecretMatch(pend.SecretSHA256, signingSecret) {' 'if !live {' $H
mutate hs-digest-noop       $HS '	return m.deps.Vault.MatchInstallSecret(signingSecret, d)' '	_ = signingSecret
	return d != [meshSigSize]byte{}' $H
mutate hs-digest-zone-noop  internal/builtin/mesh_vault.go '	return fingerprint.MatchSHA256(v, want)' '	return want != [32]byte{}' $H
mutate hs-digest-prefix     pkg/fingerprint/digest.go 'return subtle.ConstantTimeCompare(sum[:], want[:]) == 1' 'return subtle.ConstantTimeCompare(sum[:4], want[:4]) == 1' $H
mutate hs-digest-prefix16   pkg/fingerprint/digest.go 'return subtle.ConstantTimeCompare(sum[:], want[:]) == 1' 'return subtle.ConstantTimeCompare(sum[:16], want[:16]) == 1' $H
mutate hs-repeat-any-secret $HS '		if err != nil || !same {' '		if err != nil || (!same && false) {' $H
mutate hs-repeat-noop       $HS '		same, err := m.deps.Vault.SameEventsSecret(r.Context(), org.String(), ws.String(), signingSecret)' '		same, err := true, error(nil); _ = org' $H
mutate hs-same-secret-len   internal/builtin/mesh_vault.go 'same = subtle.ConstantTimeCompare(b, c) == 1' 'same = subtle.ConstantTimeEq(int32(len(b)), int32(len(c))) == 1' $H
mutate hs-skew-off          $HS '	if d := m.now().Sub(time.Unix(secs, 0)); d > meshMaxSkew || d < -meshMaxSkew {
		deny()
		return
	}
	got, err := hex.DecodeString' '	if d := m.now().Sub(time.Unix(secs, 0)); d > 1<<62 {
		deny()
		return
	}
	got, err := hex.DecodeString' $H
mutate hs-extension-open    $HS 'if err != nil || req.ExtensionID != meshext.ExtensionID ||' 'if err != nil ||' $H
mutate hs-short-secret      $HS 'len(req.SigningSecret) < meshMinSigningSecret ||' 'len(req.SigningSecret) < 1 ||' $H
mutate hs-window-expiry-off $R '`DELETE FROM mesh_pending_installs WHERE expires_at <= now()`' '`DELETE FROM mesh_pending_installs WHERE false`' $H "$R" ' AND secret_sha256 = $4 AND expires_at > now()`' ' AND secret_sha256 = $4`'
# An expired window and its digest are deleted: on lookup, on opening any
# window, and by the periodic sync round.
mutate drop-expired-off     $R '`DELETE FROM mesh_pending_installs WHERE expires_at <= now()`' '`DELETE FROM mesh_pending_installs WHERE false`' $H
mutate drop-expired-live-off $R '	if err := r.DropExpiredPending(ctx); err != nil {
		return Pending{}, false, err
	}' '' $H
mutate drop-expired-open-off $R '	if err := r.DropExpiredPending(ctx); err != nil {
		return time.Time{}, err
	}' '' $H
mutate drop-expired-sync-off cmd/keep-server/app/mesh_sync.go '	if err := repo.DropExpiredPending(ctx); err != nil {' '	if err := error(nil); err != nil {' TestMeshSyncRoundDropsExpiredWindows
mutate drop-expired-wire-off cmd/keep-server/app/mesh_sync.go '		meshSyncRound(ctx, repo, f, log)' '		repo.ReconcileAll(ctx, f, log)' TestMeshSyncLoopDropsExpiredWindows
mutate hs-window-reusable   $R 'DELETE FROM mesh_pending_installs
 WHERE workspace_id = $1 AND org_id' 'UPDATE mesh_pending_installs SET opened_at = opened_at
 WHERE workspace_id = $1 AND org_id' $H
mutate hs-bind-no-events    $HS '		return m.deps.Vault.Put(ctx, pend.Org.String(), ws.String(), meshKindEvents, signingSecret)' '		return nil' $H
mutate hs-bind-no-audit     $HS '	m.audit(r, installer, requestID, audit.StatusOK, audit.ErrClassNone)' '	_ = installer' $H
mutate hs-dispatch-always   $HS 'if _, ok := r.Header[http.CanonicalHeaderKey("Authorization")]; ok {' 'if false {' $H
mutate hs-repeat-echo       $HS '		writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
		return
	}
	pend, live' '		writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: signingSecret})
		return
	}
	pend, live' TestMeshHandshakeSecretNeverLeaks
mutate hs-refusal-log       $HS '	if !live || !m.meshSecretMatch(pend.SecretSHA256, signingSecret) {
		deny()' '	if !live || !m.meshSecretMatch(pend.SecretSHA256, signingSecret) {
		w.Header().Set("X-Debug", signingSecret)
		deny()' TestMeshHandshakeSecretNeverLeaks
# The secret is sealed only after the window is spent, and a failed seal
# binds nothing.
B=TestMeshHandshakeBindConsumesWindowBeforeSealing
mutate hs-seal-before-consume $R '	tag, err := tx.Exec(ctx, `
DELETE FROM mesh_pending_installs' '	if err := seal(ctx); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
DELETE FROM mesh_pending_installs' $B "$R" '	if err := seal(ctx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {' '	if err := tx.Commit(ctx); err != nil {'
mutate hs-seal-error-ignored  $R '	if err := seal(ctx); err != nil {' '	if err := seal(ctx); err != nil && false {' $B
mutate hs-seal-outside-tx     $HS '	if err := m.deps.Repo.BindPending(r.Context(), ws, pend, meshext.ModeExtension, func(ctx context.Context) error {
		return m.deps.Vault.Put(ctx, pend.Org.String(), ws.String(), meshKindEvents, signingSecret)
	}); err != nil {' '	if err := m.deps.Vault.Put(r.Context(), pend.Org.String(), ws.String(), meshKindEvents, signingSecret); err != nil {
		writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
		return
	}
	if err := m.deps.Repo.BindPending(r.Context(), ws, pend, meshext.ModeExtension, func(context.Context) error { return nil }); err != nil {' $B
# BindPending refuses a window that expired after the lookup on its own.
mutate hs-bind-expiry-off     $R ' AND secret_sha256 = $4 AND expires_at > now()`' ' AND secret_sha256 = $4`' $B
# The route and handler guards: TLS, limiter, lock, no-store, org match,
# journal of a refused window.
G=TestMeshHandshakeGuards
RT=internal/api/router.go
mutate hs-tls-off             $RT 'requireTLS(http.HandlerFunc(mr.handleHandshake))' 'http.HandlerFunc(mr.handleHandshake)' $G
mutate hs-limiter-off         $HS 'if allowed, wait := m.install.take(bucketKey{id: ws}); !allowed {' 'if allowed, wait := m.install.take(bucketKey{id: ws}); !allowed && false {' $G
mutate hs-limiter-noop        $HS 'if allowed, wait := m.install.take(bucketKey{id: ws}); !allowed {' 'if allowed, wait := true, 0; !allowed {' $G
mutate hs-lock-noop           $HS 'unlock, err := m.deps.Repo.LockWorkspace(r.Context(), ws)' 'unlock, err := func() {}, error(nil)' $G
mutate hs-no-store-off        $HS '	m.audit(r, installer, requestID, audit.StatusOK, audit.ErrClassNone)
	w.Header().Set("Cache-Control", "no-store")' '	m.audit(r, installer, requestID, audit.StatusOK, audit.ErrClassNone)' $G
mutate pending-no-store-off   $HS '	m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusOK, audit.ErrClassNone)
	w.Header().Set("Cache-Control", "no-store")' '	m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusOK, audit.ErrClassNone)' $G
mutate pending-org-match-off  $RT 'chain(requireTLS, authenticate(ir, logger, false), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall))' 'chain(requireTLS, authenticate(ir, logger, false))(http.HandlerFunc(mr.handlePendingInstall))' $G
mutate pending-denied-no-audit $HS '		m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusNotFound' '		writeError(w, http.StatusNotFound' $G
W=TestMeshPendingInstallWindow
mutate pending-admin-off    $HS '		m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusNotFound' '		_ = admin
	}
	if false {
		writeError(w, http.StatusNotFound' $W
mutate pending-sha-short    $HS '	if len(h) != 2*meshSigSize {' '	if len(h) < 8 {' $W
mutate pending-sha-long     $HS '	if len(h) != 2*meshSigSize {' '	if len(h) < 2*meshSigSize {' $W
mutate pending-foreign-ws   $R '	} else if found && org != p.Org {' '	} else if found && org != p.Org && false {' $W
mutate pending-steal-window $R ' WHERE mesh_pending_installs.org_id = EXCLUDED.org_id OR mesh_pending_installs.expires_at <= now()' '' $W
mutate pending-no-audit     $HS '	m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusOK, audit.ErrClassNone)' '	_ = p' $W
mutate pending-tls-off        $RT 'chain(requireTLS, authenticate(ir, logger, false), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall))' 'chain(authenticate(ir, logger, false), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall))' $W
mutate pending-auth-off       $RT 'chain(requireTLS, authenticate(ir, logger, false), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall))' 'chain(requireTLS, identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall))' $W
# The route's own role gate, not only the outer one: open the pattern to the
# poller in pollerGate too, or the outer gate alone would keep the test green.
mutate pending-poller-allowed $RT 'chain(requireTLS, authenticate(ir, logger, false), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall))' 'chain(requireTLS, authenticate(ir, logger, true), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall))' $G internal/api/restarts.go '	"POST /v1/restarts/claim":            true,' '	"POST /v1/restarts/claim":            true,
	"POST /orgs/{org_id}/mesh/pending-installs": true,'
mutate pending-digest-echo    $HS 'writeJSON(w, http.StatusCreated, MeshPendingResult{WorkspaceID: ws.String(), ExpiresAt: expires.UTC().Format(time.RFC3339), RequestID: requestID})' 'writeJSON(w, http.StatusCreated, MeshPendingResult{WorkspaceID: ws.String(), ExpiresAt: expires.UTC().Format(time.RFC3339), RequestID: req.SigningSecretSHA256})' TestMeshHandshakeSecretNeverLeaks
mutate pending-digest-b64    $HS '	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated' '	if d, err := hex.DecodeString(req.SigningSecretSHA256); err == nil {
		w.Header().Set("X-Window", base64.RawStdEncoding.EncodeToString(d))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated' TestMeshHandshakeSecretNeverLeaks internal/api/mesh_handshake.go '	"encoding/hex"' '	"encoding/base64"
	"encoding/hex"'
mutate pending-digest-prefix $HS 'RequestID: requestID})
}' 'RequestID: requestID[:0] + req.SigningSecretSHA256[:16]})
}' TestMeshHandshakeSecretNeverLeaks
mutate pending-unknown-fields $HS '	dec.DisallowUnknownFields()' '	_ = dec' $W
mutate pending-sha-hex-open   $HS "		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {" '		if c == 0 {' $W

# POST /mesh/token: Mesh delivers the actor token; it is sealed for its own
# installation, a replay cannot put back an older one, and it is on no surface.
pkg=./cmd/keep-server/app
T=internal/api/mesh_token.go
TO=TestMeshTokenDeliveryOutcomes
TL=TestMeshTokenDeliveryNeverLeaks
mutate delivery-route-off        internal/api/router.go '		mux.Handle("POST /mesh/token", logged("/mesh/token", logger, requireTLS(http.HandlerFunc(mr.handleToken)).ServeHTTP))' '		_ = mr.handleToken' $TL
mutate delivery-tls-off          internal/api/router.go 'requireTLS(http.HandlerFunc(mr.handleToken)).ServeHTTP' 'mr.handleToken' $TO
mutate delivery-echoed           $T '	writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})' '	writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: string(req.ExtensionToken)})' $TL
mutate delivery-not-sealed       $T 'meta, perr = m.deps.Vault.PutToken(ctx, org.String(), ws.String(), string(req.ExtensionToken))' 'meta, perr = MeshSecretMeta{}, error(nil)' $TO
mutate delivery-other-install    $T 'm.deps.Vault.PutToken(ctx, org.String(), ws.String(), string(req.ExtensionToken))' 'm.deps.Vault.PutToken(ctx, org.String(), uuid.Nil.String(), string(req.ExtensionToken))' $TO
mutate delivery-path-of-org      internal/builtin/mesh_vault.go '	path, err := meshPath(workspace, MeshExtensionToken)
	if err != nil || token == "" {' '	path, err := meshPath(org, MeshExtensionToken)
	if err != nil || token == "" {' $TO
mutate delivery-sig-off          $T '	if err != nil || !valid {' '	if _ = valid; false {' $TO
mutate delivery-skew-off         $T 'if d := m.now().Sub(time.Unix(secs, 0)); d > meshMaxSkew || d < -meshMaxSkew {' 'if d := m.now().Sub(time.Unix(secs, 0)); d > 1<<62 {' $TO
mutate delivery-ext-id-open      $T 'req.ExtensionID != meshext.ExtensionID ||' '' $TO
mutate delivery-max-off          $T ' || len(req.ExtensionToken) > meshMaxTokenLen' '' $TO
mutate delivery-replay-open      internal/meshext/repo.go ' AND (token_signed_at IS NULL OR token_signed_at < $3)`,' '`,' $TO
mutate delivery-same-second-ok   internal/meshext/repo.go 'token_signed_at < $3)' 'token_signed_at <= $3)' $TO
mutate delivery-seal-unordered   internal/meshext/repo.go '	if tag.RowsAffected() != 1 {
		return ErrStaleToken
	}' '	_ = tag' $TO
mutate delivery-ack-unjournaled  $T 'if err := m.auditSecret(r, org, ws, audit.ActionMeshToken, "", meta, audit.StatusOK, audit.ErrClassNone); err != nil {' 'if m.auditSecret(r, org, ws, audit.ActionMeshToken, "", meta, audit.StatusOK, audit.ErrClassNone) != nil && false {' TestMeshTokenNoAcknowledgementWithoutAuditRecord
mutate delivery-refusal-unjournaled $T 'if err := m.auditSecret(r, org, ws, audit.ActionMeshToken, "", MeshSecretMeta{}, audit.StatusFailed, class); err != nil {' 'if err := error(nil); err != nil {' $TO
mutate delivery-refusal-unacknowledged $T 'if err := m.auditSecret(r, org, ws, audit.ActionMeshToken, "", MeshSecretMeta{}, audit.StatusFailed, class); err != nil {' 'if m.auditSecret(r, org, ws, audit.ActionMeshToken, "", MeshSecretMeta{}, audit.StatusFailed, class) != nil && false {' TestMeshTokenNoAcknowledgementWithoutAuditRecord
mutate delivery-signed-fields-unjournaled $T '		refuse(audit.ErrClassInvalidArgument)' '		deny()' TestMeshTokenNoAcknowledgementWithoutAuditRecord
# One answer for every refusal, and the guard committed before the seal under
# a per-workspace lock.
TR=TestMeshTokenRefusalsShareOneAnswer
TG=TestMeshTokenGuardCommitsBeforeSeal
mutate delivery-oversize-400   $T '	if err != nil {
		deny()
		return
	}
	tsRaw' '	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	tsRaw' $TR
mutate delivery-throttle-429   $T '!allowed {
		deny()' '!allowed {
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, "too many requests; retry later", requestID)' $TR
mutate delivery-throttle-off   $T 'if allowed, _ := m.install.take(bucketKey{id: ws}); !allowed {' 'if _, _ = m.install.take(bucketKey{id: ws}); false {' $TR
# The budget spent before the signature is checked: forged deliveries starve
# a signed one.
mutate delivery-throttle-before-auth $T '	org, found, err := m.deps.Repo.Owner(r.Context(), ws)' '	if allowed, _ := m.install.take(bucketKey{id: ws}); !allowed {
		deny()
		return
	}
	org, found, err := m.deps.Repo.Owner(r.Context(), ws)' TestMeshTokenBadSignaturesDoNotSpendTheBudget $T '	if allowed, _ := m.install.take(bucketKey{id: ws}); !allowed {
		deny()
		return
	}
	// Signed by' '	// Signed by'
mutate delivery-guard-in-seal-tx internal/meshext/repo.go '	tag, err := conn.Exec(ctx, `
UPDATE mesh_installations SET token_signed_at' '	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tag, err := tx.Exec(ctx, `
UPDATE mesh_installations SET token_signed_at' $TG internal/meshext/repo.go '	return seal(ctx)
}' '	if err := seal(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}'
mutate delivery-unlocked       internal/meshext/repo.go 'SELECT pg_advisory_lock(hashtextextended($1 || $2::text, 0))' 'SELECT $1 || $2::text' $TG
# A delivery and a reinstall take one workspace lock: under a second name a
# delivery seals mid-reinstall and the failed reinstall's rollback restores
# the older token.
mutate delivery-own-lock       internal/meshext/repo.go '	conn, unlock, err := r.lock(ctx, workspaceLock, workspace)' '	conn, unlock, err := r.lock(ctx, "mesh-token:", workspace)' TestMeshTokenDeliveryWaitsForFailingReinstall
# Waiting deliveries count against the lock slots: without the bound each
# holds a connection and the lock owner waits forever for one to seal on.
mutate delivery-pool-unbounded internal/meshext/repo.go 'lockSlots: make(chan struct{}, n)}' 'lockSlots: make(chan struct{}, n+64)}' TestMeshTokenWaitingDeliveriesDoNotExhaustThePool

# Test failure messages name an error class only as an apperr constant: echoing
# the answer's class, or any lowercase string, would put answer text back into
# the output the canary check above reads.
pkg=./cmd/keep-server/app
mutate answer-diag-echo cmd/keep-server/app/mesh_test.go '	for _, c := range apperr.Classes() {
		if string(c) == e.ErrorClass {
			class = string(c)
		}
	}' '	class = e.ErrorClass
	_ = apperr.Classes' TestAnswerDiagPrintsOnlyKnownClasses
# The pre-authentication limit (per client address, before any storage call,
# token back on success) and the workspace's handshake budget spent only once
# the handshake authenticated.
pkg=./internal/api
CA=internal/api/clientaddr.go
P=TestMeshPreauthLimitStopsBadSignaturesBeforeStorage
mutate preauth-take-off       $A '	allowed, wait := m.preauth.take(k)' '	allowed, wait := true, 0
	_ = k' $P
mutate preauth-events-noop    $A '	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return
	}
	org, found, err' '	refund, ok := func() {}, true
	if !ok {
		return
	}
	org, found, err' $P
mutate preauth-secrets-noop   $A '	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}' '	refund, ok := func() {}, true
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}' $P
mutate preauth-handshake-noop $HS '	refund, ok := m.preauthTake(w, r, requestID)' '	refund, ok := func() {}, true' $P
mutate preauth-token-noop     $T '	refund, ok := m.preauthTake(w, r, requestID)' '	refund, ok := func() {}, true' $P
mutate preauth-key-per-request $A '	k := addrKey(clientAddr(r, m.deps.TrustedProxies))' '	k := bucketKey{id: [16]byte(uuid.New())}' $P
mutate xff-from-any-peer      $CA '	if !peer.IsValid() || !inPrefixes(peer, trusted) {' '	if !peer.IsValid() {' TestMeshPreauthIgnoresForwardedForFromUntrustedPeer
mutate xff-step-over-garbage  $CA '		if err != nil {
			return addrBucket(peer)
		}' '		if err != nil {
			continue
		}' TestClientAddr
mutate xff-leftmost           $CA '	for i := len(hops) - 1; i >= 0; i-- {' '	for i := 0; i < len(hops); i++ {' TestClientAddr
mutate ipv6-not-aggregated    $CA '	p, _ := a.WithZone("").Prefix(64)' '	p, _ := a.WithZone("").Prefix(128)' TestClientAddr
mutate ipv4-mapped-kept       $CA '		return ap.Addr().Unmap()' '		return ap.Addr()' TestClientAddr
mutate preauth-warn-debug     $A '				m.logger.Warn("mesh pre-authentication' '				m.logger.Debug("mesh pre-authentication' TestMeshPreauthWarnsOnceOnLoopbackWithoutProxies
mutate preauth-warn-every-time $A '			m.warnLoopOnce.Do(func() {' '			func(f func()) { f() }(func() {' TestMeshPreauthWarnsOnceOnLoopbackWithoutProxies
pkg=./internal/config
mutate proxies-unmasked       internal/config/config.go '		out = append(out, p.Masked())' '		out = append(out, p)' TestTrustedProxiesFromEnv
mutate proxies-error-ignored  internal/config/config.go '		if err != nil {
			return nil, errors.New("KEEP_TRUSTED_PROXIES' '		if err != nil && false {
			return nil, errors.New("KEEP_TRUSTED_PROXIES' TestTrustedProxiesFromEnv
pkg=./cmd/keep-server/app
mutate hs-budget-before-verify $HS '	refund, ok := m.preauthTake(w, r, requestID)' '	if !m.takeInstall(w, ws, requestID) {
		return
	}
	refund, ok := m.preauthTake(w, r, requestID)' TestMeshPreauthBadHandshakesDoNotLockOutWorkspace
mutate events-no-refund       $A '	refund()

	ev, err := meshext.ParseEvent(' '	_ = refund

	ev, err := meshext.ParseEvent(' TestMeshPreauthBadEventsDoNotLockOutWorkspace
mutate secrets-refund-before-nonce $A '	// Only a fresh nonce gets the token back: a replayed signed call stays
	// on the caller'"'"'s budget.
	refund()
' '' TestMeshPreauthSecretsRefundOnlyFreshNonce $A '	if err != nil || !valid {
		return deny()
	}
	// The nonce is spent' '	if err != nil || !valid {
		return deny()
	}
	refund()
	// The nonce is spent'
mutate hs-refund-bound-off    $HS '		refund()
		if !m.takeInstall(w, ws, requestID) {' '		_ = refund
		if !m.takeInstall(w, ws, requestID) {' TestMeshPreauthHandshakeRefundsOnAuthentication
mutate hs-refund-window-off   $HS '	refund()
	if !m.takeInstall(w, ws, requestID) {' '	_ = refund
	if !m.takeInstall(w, ws, requestID) {' TestMeshPreauthHandshakeRefundsOnAuthentication
mutate trusted-proxies-unwired cmd/keep-server/app/main.go 'KeyLevels:  keyLevels, TrustedProxies: cfg.TrustedProxies}' 'KeyLevels:  keyLevels}' TestMeshDepsCarryTrustedProxies
mutate preauth-token-refund-early $T '	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return
	}' '	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return
	}
	refund()' TestMeshPreauthLimitsTokenDelivery $T '	refund()
	// The workspace' '	// The workspace'
mutate preauth-token-no-refund $T '	refund()
	// The workspace' '	_ = refund
	// The workspace' TestMeshPreauthLimitsTokenDelivery
mutate preauth-session-noop   $A '	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return
	}
	handle, _, err' '	refund, ok := func() {}, true
	if !ok {
		return
	}
	handle, _, err' TestMeshPreauthLimitsSessionSignIn

R=internal/meshext/repo.go
U=internal/api/mesh_uninstall.go
# Removal of an installation: erasure first and for real, the delete, a failed
# erasure keeping the row, the admin and organisation bounds, the workspace
# lock shared with secret writes.
mutate uninstall-erase-noop   $R 'erased, err := erase(ctx, tx)' 'erased, err := 0, error(nil); _ = erase' TestMeshUninstallErasesAndCascades
mutate uninstall-vault-erase-noop internal/builtin/mesh_vault.go 'if err := p.Erase(ctx, provider.Ref{Path: v.secretID, Version: versionString(v.version)}); err != nil {' 'if err := func() error { _ = v; return nil }(); err != nil {' TestMeshUninstallErasesAndCascades
mutate uninstall-erase-prefix-off internal/builtin/store.go 'AND left(secret_id, $5) = $6 AND (wrapped_dek' 'AND length($6) >= $5 AND (wrapped_dek' TestMeshUninstallErasesAndCascades
mutate uninstall-delete-off   $R 'DELETE FROM mesh_installations WHERE workspace_id = $1 AND org_id = $2' 'SELECT 1 WHERE $1::uuid IS NOT NULL AND $2::uuid IS NOT NULL' TestMeshUninstallErasesAndCascades
mutate uninstall-erase-error-ignored $R '	erased, err := erase(ctx, tx)
	if err != nil {
		return 0, err
	}' '	erased, err := erase(ctx, tx)
	_ = err' TestMeshUninstallEraseFailureKeepsInstallation
mutate uninstall-orphans-kept $R '		if _, err := erase(ctx, tx); err != nil {
			return 0, err
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("meshext: uninstall: %w", err)
		}
		return 0, ErrNotInstalled' '		return 0, ErrNotInstalled' TestMeshUninstallErasesOrphanedCredentials
mutate uninstall-erase-outside-tx internal/builtin/mesh_vault.go '	p.db = p.db.withTx(tx)' '	_ = tx' TestMeshUninstallEraseFailureKeepsInstallation
mutate uninstall-pending-off  $U 'if m.auditUninstall(r, p, requestID, "", audit.StatusPending, audit.ErrClassNone) != nil {' 'if false {' TestMeshUninstallNoRemovalWithoutAuditRecord
mutate uninstall-final-audit-ignored $U 'if m.auditUninstall(r, p, requestID, reason, result, ec) != nil {' 'if m.auditUninstall(r, p, requestID, reason, result, ec) != nil && false {' TestMeshUninstallNoRemovalWithoutAuditRecord
mutate uninstall-erase-skips-disabled internal/builtin/store.go "(wrapped_dek IS NOT NULL OR kek_id IS NOT NULL OR status <> 'erased')" "status = 'active'" TestMeshUninstallErasesAndCascades
mutate uninstall-window-kept  $R 'DELETE FROM mesh_pending_installs WHERE workspace_id = $1 AND org_id = $2' 'SELECT 1 WHERE $1::uuid IS NOT NULL AND $2::uuid IS NOT NULL' TestMeshUninstallErasesAndCascades
mutate uninstall-reason-fingerprint $U '" erased="+strconv.Itoa(erased)' '" erased="+strconv.Itoa(erased)+" kfp1:k1:abcdefghij"' TestMeshUninstallNeverLeaks
mutate uninstall-admin-off    $U 'if !admin {' 'if !admin && false {' TestMeshUninstallAuthorization
mutate uninstall-org-unbound  $R 'WHERE workspace_id = $1 AND org_id = $2 FOR UPDATE' 'WHERE workspace_id = $1 AND $2::uuid IS NOT NULL FOR UPDATE' TestMeshUninstallAuthorization $R 'DELETE FROM mesh_installations WHERE workspace_id = $1 AND org_id = $2' 'DELETE FROM mesh_installations WHERE workspace_id = $1 AND $2::uuid IS NOT NULL'
mutate uninstall-lock-off     $R '	conn, unlock, err := r.lock(ctx, workspaceLock, workspace)
	if err != nil {
		return 0, fmt.Errorf("meshext: uninstall: %w", err)' '	conn, unlock, err := r.lock(ctx, workspaceLock+"x", workspace)
	if err != nil {
		return 0, fmt.Errorf("meshext: uninstall: %w", err)' TestMeshUninstallSerializesWithSecretWrites
mutate secret-put-lock-off    $R '	conn, unlock, err := r.lock(ctx, workspaceLock, workspace)
	if err != nil {
		return fmt.Errorf("meshext: lock workspace: %w", err)' '	conn, unlock, err := r.lock(ctx, workspaceLock+"x", workspace)
	if err != nil {
		return fmt.Errorf("meshext: lock workspace: %w", err)' TestMeshUninstallSerializesWithSecretWrites
mutate secret-put-unguarded   $A 'err = m.deps.Repo.WhileInstalled(r.Context(), ws, org, func(ctx context.Context) error {' 'err = func(fn func(context.Context) error) error { return fn(r.Context()) }(func(ctx context.Context) error {' TestMeshUninstallSerializesWithSecretWrites

# The unmutated tree is green with nothing skipped.
if mutation_apply_only; then
	:
elif (cd "$root" && go test -count=1 -p 1 -json -run 'TestMesh' ./cmd/keep-server/app ./internal/meshext >"$work/base" 2>&1) && ! grep -q -- '--- SKIP' "$work/base" && [ "$(grep -c -- '--- PASS' "$work/base")" -ge 35 ]; then
	echo "ok   baseline: Mesh tests green on the real code, none skipped"
else
	echo "FAIL baseline: Mesh tests red or skipped on the real code"
	# Declared test names and their file:line only; log text is never echoed.
	echo "baseline PASS count: $(grep -c -- '--- PASS' "$work/base" || true) (need >= 35)"
	"$root/scripts/baseline-diagnostics.sh" "$root" <"$work/base" || true
	mutation_infrastructure_counts "$work/base"
	fail=1
fi
mutation_shard_finish
exit $fail
