#!/bin/sh
# Proves the runner-enrollment security properties can fail (review-round
# finding: a property without a mutation guard is a gap). In a scratch copy
# of the tree, switch off one property at a time and require the property's
# own test to go red:
#
#   ca-pair       — Lookup authenticates public CA/signing material against
#                    its sealed envelope before trusting it. This supersedes
#                    the issuance-only key-pair mutation: x509 already rejects
#                    mismatched pairs, and the earlier AEAD check now does too.
#   ca-request    — the production request adapter uses the authenticated
#                    public CA cache rather than reopening sealed key material.
#   ca-cache      — Ensure publishes its authenticated CA for mTLS requests.
#   ca-isolation  — one corrupt organization CA does not deny healthy tenants.
#   tls-config    — the server rejects an absent TLS pair without the explicit
#                    development flag.
#   ca-reason     — a missing CA and a bad chain share one public log reason.
#   maxpathlen    — the org CA template is a leaf-only CA (MaxPathLenZero).
#   csr-sig       — IssueRunnerCert refuses a CSR with a tampered signature.
#   leaf-eku      — the runner certificate orgpki issues carries
#                    ExtKeyUsageClientAuth, nothing broader.
#   org-bind      — the CA private key's sealed envelope (ca_kek_id/
#                    ca_wrapped_dek/ca_ciphertext) is bound to the owning
#                    organization, not just stored in a row keyed by org_id.
#   leaf-keymatch — internal/runner.Load refuses a runner certificate whose
#                    public key does not match the stored private key.
#   chain         — internal/runner.Load refuses a runner certificate that
#                    does not chain to the pinned org CA.
#   signlen       — internal/runner.Load refuses a job-signing public key of
#                    the wrong length.
#   cred-mode     — internal/runner.Load refuses an on-host credential key
#                    file wider than mode 0600.
#   cred-nofollow — internal/runner.Load refuses a symlinked credential key
#                    file.
#   rk-mode       — builtin's readLocalRoot refuses a root key file
#                    wider than mode 0600.
#   rk-nofollow   — readLocalRoot refuses a symlinked root key file.
#   mtls-chain    — internal/mtls.RequireMTLS refuses a client certificate
#                    that does not chain to the presented org's real CA.
#   mtls-eku      — RequireMTLS enforces ExtKeyUsageClientAuth itself, not
#                    just whatever orgpki happens to issue.
#   reg-revoked   — internal/registry.CheckActive refuses a revoked runner.
#   reg-stale     — CheckActive refuses a certificate serial that is not the
#                    runner's current one (superseded by a renewal).
#   tok-host      — enrolltoken.Redeem refuses a token presented for a host
#                    other than the one it was issued for.
#   tok-policy    — Redeem refuses a token whose policy hash does not match.
#   tok-expiry    — Redeem refuses a token past its expiry.
#   tok-race      — Redeem's mark-used UPDATE is guarded by "AND used_at IS
#                    NULL", checked against live database state rather than
#                    the in-memory used_at read earlier in the same call.
#                    This is what actually refuses reuse, sequential or
#                    concurrent: Redeem's own early "if usedAt != nil" read-
#                    time check is provably redundant with it (confirmed by
#                    trying to mutate the early check alone — the reuse test
#                    stayed green, because by the second call the row's
#                    used_at is already set in the database regardless of
#                    what the first call's in-memory copy said), so it gets
#                    no mutate line of its own here — nothing but this guard
#                    is load-bearing for reuse.
#   requireTLS    — internal/api's requireTLS middleware refuses a request
#                    that did not arrive over the TLS listener.
#   https-runner  — keep-runner enroll refuses a non-https -server before the
#                    enrollment token or the CSR ever leave the process.
#   redir-runner  — keep-runner enroll does not follow a redirect to a
#                    different (or downgraded-to-plain-http) origin.
#   https-keep    — keep runner enroll-token/revoke refuse a non-https
#                    -server before the admin bearer token is sent.
#   redir-keep    — keep runner enroll-token does not follow a redirect to a
#                    different (or downgraded-to-plain-http) origin.
#
# internal/builtin/orgpki, internal/registry and internal/enrolltoken need a
# real, disposable PostgreSQL (KEEP_DATABASE_URL, CONTRIBUTING.md — never
# mocked); internal/runner, internal/mtls, internal/api and cmd/keep-server
# need none (no TestMain in any of them dials a database). KEEP_DATABASE_URL
# is still required up front so a missing database fails loudly here instead
# of turning into a silent SKIP inside one mutation. Exits 0 only if every
# mutation is caught and the real code is green with zero SKIPs.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
test -f "$root/go.mod" || { echo "refuse: $root is not the repo root" >&2; exit 2; }

# Private per-run build cache and scratch workspace, both removed on exit
# (see scripts/lib/gocache.sh, scripts/temp-workspace.sh). Respects an
# already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace

if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo 'runner-enroll mutations: a migrated PostgreSQL database is required' >&2
	exit 2
fi

fail=0

# mutate NAME FILE PKG FROM TO WANT: FILE is repo-root-relative (mutations
# span three packages). Replaces the first literal occurrence of FROM with
# TO in a scratch copy and requires `go test -run WANT` in PKG to go red.
# Naming the test is the point: a mutant that turns some unrelated test red
# proves nothing about the guard it is meant to exercise. A WANT that
# matches nothing, or whose test SKIPs, is a failure too, not a pass.
mutate() {
	name=$1 src=$2 pkg=$3 from=$4 to=$5 want=$6
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
	if (cd "$work/tree" && KEEP_DATABASE_URL="$KEEP_DATABASE_URL" go test -count=1 -run "$want" -v "$pkg" >"$work/out" 2>&1); then
		echo "FAIL $name: $want stayed green with the property switched off"
		fail=1
	elif grep -q -- '--- SKIP' "$work/out"; then
		echo "FAIL $name: $want SKIPped"
		fail=1
	elif ! grep -q -- '^--- FAIL' "$work/out"; then
		# Red because the mutant does not build is not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: $want went red ($(grep -c -- '^--- FAIL' "$work/out") failing)"
	fi
}

orgpki=internal/builtin/orgpki/orgpki.go
credential=internal/runner/credential_unix.go
rootkey=internal/builtin/local_unix.go
mtls=internal/mtls/middleware.go
registry=internal/registry/repo.go
enrolltoken=internal/enrolltoken/repo.go
runnersapi=internal/api/runners.go
runnerenroll=cmd/keep-runner/enroll.go
keeprunnercli=cmd/keep/runner.go

mutate restart-keystore internal/builtin/store.go ./internal/builtin/orgpki/... \
 'FROM keep_kek WHERE org_id = $1 AND id = $2' \
 'FROM keep_kek WHERE false AND org_id = $1 AND id = $2' \
 '^TestIssueRunnerCert_PersistsAcrossRestart$'

mutate ca-process-output "$orgpki" ./internal/builtin/orgpki/... \
 'defer wipe(caPriv)' \
 'defer wipe(caPriv); fmt.Printf("%x", caPriv)' \
 '^TestCAPrivateKeyNeverLeaksInServerProcess$'

# Feed the error-response assertion deliberately bad bytes after the real
# server has returned its rejection. This proves that the response body,
# independently of process output, is actually scanned by the leak guard.
mutate ca-process-error-response internal/builtin/orgpki/process_test.go ./internal/builtin/orgpki/... \
 'errorResponse, err := io.ReadAll(resp.Body)' \
 'errorResponse, err := io.ReadAll(resp.Body); errorResponse = append(errorResponse, key...)' \
 '^TestCAPrivateKeyNeverLeaksInServerProcess$'

mutate token-process-output "$runnersapi" ./cmd/keep-server/... \
 'redeemed, err := tokens.Redeem' \
 'println(req.Token); redeemed, err := tokens.Redeem' \
 '^TestRunnerEnrollmentTokenNeverLeaksInProcessOutput$'

mutate tenant-from-header "$mtls" ./internal/mtls/... \
 'return Principal{OrgID: orgID, RunnerID: runnerID, Host: host, Serial: serial}' \
 'if headerOrg, err := uuid.Parse(r.Header.Get("X-Org-Id")); err == nil { orgID = headerOrg }; return Principal{OrgID: orgID, RunnerID: runnerID, Host: host, Serial: serial}' \
 '^TestRequireMTLS_BodyAndHeaderOrgIDAreIgnored$'

mutate enrollment-audit "$runnersapi" ./internal/api/... \
 'audit.ActionRunnerEnrollTokenIssue' \
 'audit.ActionRunnerEnroll' \
 '^TestRunnerEnrollmentWritesIssueAndUseAudit$'

# Remove the append call while leaving the successful revocation intact.
mutate runner-revoke-audit "$runnersapi" ./internal/api/... \
 'if err := appendRunnerRevokeAudit(r.Context(), aud, principal, runnerID, requestID); err != nil {' \
 'if err := error(nil); err != nil {' \
 '^TestRevokeRunner_WritesAuditWithoutCredentials$'

mutate ca-pair "$orgpki" ./internal/builtin/orgpki/... \
 'if err := r.authenticateBundle(ctx, orgID, rec); err != nil {' \
 'if err := r.authenticateBundle(ctx, orgID, rec); false && err != nil {' \
 '^TestLookupAuthenticatesPublicMaterial$'

mutate ca-request cmd/keep-server/app/runners.go ./cmd/keep-server/... \
 'der, ok := a.repo.CachedCACert(orgID)' \
 'bundle, _, err := a.repo.Lookup(context.Background(), orgID); der := bundle.CACertDER; ok := err == nil' \
 '^TestProductionCAResolverUsesAuthenticatedCache$'

mutate ca-cache "$orgpki" ./internal/builtin/orgpki/... \
 'r.verificationCAs[orgID] = append([]byte(nil), der...)' \
 'delete(r.verificationCAs, orgID)' \
 '^TestVerificationCacheNeverOpensKeysForClaimedOrganization$'

mutate ca-isolation "$orgpki" ./internal/builtin/orgpki/... \
 'continue' \
 'return errors.New("orgpki: one CA failed")' \
 '^TestVerificationCacheIsolatesCorruptOrganization$'

mutate tls-config cmd/keep-server/app/runners.go ./cmd/keep-server/... \
 'if !cfg.DevEphemeralTLS {' \
 'if false {' \
 '^TestServerTLSRequiresExplicitCertificateOrDevelopmentFlag$'

mutate ca-reason "$mtls" ./internal/mtls/... \
 'return Principal{}, "chain_verification_failed", errChainVerification' \
 'return Principal{}, "unknown_org", errChainVerification' \
 '^TestRequireMTLS_MissingCAAndBadChainShareAuthenticationReason$'

mutate maxpathlen "$orgpki" ./internal/builtin/orgpki/... \
	'MaxPathLenZero:        true,' \
	'MaxPathLenZero:        false,' \
	'^TestEnsureGeneratesAndPersists$'

mutate csr-sig "$orgpki" ./internal/builtin/orgpki/... \
	'if err := csr.CheckSignature(); err != nil {' \
	'if false {' \
	'^TestIssueRunnerCertRejectsTamperedSignature$'

mutate leaf-eku "$orgpki" ./internal/builtin/orgpki/... \
	'ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},' \
	'ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},' \
	'^TestIssueRunnerCertSignsVerifiableCertIgnoringCSRSubject$'

mutate org-bind "$orgpki" ./internal/builtin/orgpki/... \
	'sealer.Ref{Store: sealer.Scope{Org: orgID.String(), PKI: true}, SecretID: "org-ca"' \
	'sealer.Ref{Store: sealer.Scope{Org: "shared", PKI: true}, SecretID: "org-ca"' \
	'^TestOrgCAEnvelopeNotOpenableAcrossOrgs$'

mutate leaf-keymatch "$credential" ./internal/runner/... \
	'if !ok || !leafPub.Equal(key.Public().(ed25519.PublicKey)) {' \
	'if false && (!ok || !leafPub.Equal(key.Public().(ed25519.PublicKey))) {' \
	'^TestLoadCredentialRefusesCertKeyMismatch$'

mutate chain "$credential" ./internal/runner/... \
	'if err := leaf.CheckSignatureFrom(caCert); err != nil {' \
	'if err := leaf.CheckSignatureFrom(caCert); false && err != nil {' \
	'^TestLoadCredentialRefusesCertNotChainedToCA$'

mutate signlen "$credential" ./internal/runner/... \
	'if len(signPubKey) != ed25519.PublicKeySize {' \
	'if false {' \
	'^TestLoadCredentialRefusesWrongLengthSignPubKey$'

mutate cred-mode "$credential" ./internal/runner/... \
	'case fi.Mode().Perm()&0o077 != 0:' \
	'case false:' \
	'^TestLoadCredentialRefusesWideKeyPermissions$'

mutate cred-mode-process "$credential" ./cmd/keep-runner/... \
 'case fi.Mode().Perm()&0o077 != 0:' \
 'case false:' \
 '^TestRunnerEnrollmentLiveRoundTrip$'

mutate cred-nofollow "$credential" ./internal/runner/... \
	'os.O_RDONLY|syscall.O_NOFOLLOW' \
	'os.O_RDONLY' \
	'^TestLoadCredentialRefusesSymlinkedKey$'

mutate rk-mode "$rootkey" ./internal/builtin/ \
	'st.Mode&0777 != 0600' \
	'false' \
	'^TestReadRootKeyFileRefusesWideMode$'

mutate rk-nofollow "$rootkey" ./internal/builtin/ \
	'unix.O_RDONLY|unix.O_NOFOLLOW' \
	'unix.O_RDONLY' \
	'^TestReadRootKeyFileRefusesSymlink$'

# Verify at request time, rather than pretending the request arrived at issuance.
mutate mtls-expiry "$mtls" ./internal/mtls/... \
 'Roots:     pool,' \
 'Roots:     pool, CurrentTime: leaf.NotBefore.Add(1e9),' \
 '^TestRequireMTLS_RejectsExpiredCertificate$'

# Collapse only the KEK domain: the lifecycle test must catch value purge
# destroying PKI even with a correctly shared process root.
mutate pki-value-domain internal/builtin/sealer/level.go ./internal/builtin/orgpki/... \
 'return "pki:" + lp(s.Org)' \
 'return "org:" + lp(s.Org)' \
 '^TestPKISurvivesValueRewrapAndPurge$'

mutate pki-store-domain internal/builtin/store.go ./internal/builtin/orgpki/... \
 'rec.Domain.PKI = strings.HasPrefix(domainKey, "pki:")' \
 'rec.Domain.PKI = false && strings.HasPrefix(domainKey, "pki:")' '^TestPKISurvivesValueRewrapAndPurge$'

mutate root-error-leak internal/builtin/local.go ./internal/builtin/ \
 'if n != 32 {' \
 'if n != 32 { return nil, errors.New("invalid root key file: " + string(encoded))' \
 '^TestRootKeyFormatsAndClosedErrors$'
mutate root-decoded-error-leak internal/builtin/local.go ./internal/builtin/ \
 'if n != 32 {' \
 'if n != 32 { return nil, errors.New("invalid root key file: " + string(key))' \
 '^TestRootKeyFormatsAndClosedErrors$'
mutate root-decoded-prefix-leak internal/builtin/local.go ./internal/builtin/ \
 'if n != 32 {' \
 'if n != 32 { return nil, errors.New("invalid root key file: " + string(key[:12]))' \
 '^TestRootKeyFormatsAndClosedErrors$'
# Removing only the format check would still fail in NewLocal's length
# guard, so emulate the old path by taking 32 decoded bytes unconditionally.
mutate root-decoded-length internal/builtin/local.go ./internal/builtin/ \
 'if n != 32 {' 'n = 32; if false {' '^TestRootKeyFormatsAndClosedErrors$'
mutate root-ambiguous-raw internal/builtin/local.go ./internal/builtin/ \
 'err == nil { // ambiguous root' 'false && err == nil { // ambiguous root' \
 '^TestRootKeyFormatsAndClosedErrors$'
mutate root-key-wipe internal/builtin/local.go ./internal/builtin/ \
 'defer clear(raw)' 'defer func() { _ = raw }()' '^TestNewLocalConsumesRoot$'
mutate root-decoded-wipe internal/builtin/local.go ./internal/builtin/ \
 'clear(key[:])' '_ = key' \
 '^TestRootBuffersWiped$/decode-error$'
mutate root-encoded-wipe internal/builtin/local.go ./internal/builtin/ \
 'defer clear(encoded) // encoded root' 'defer func() { _ = encoded }() // encoded root' \
 '^TestRootBuffersWiped$'
mutate root-read-wipe "$rootkey" ./internal/builtin/ \
 'clear(raw[:])' '_ = raw' \
 '^TestRootReadFailureWipesPartial$'
mutate root-file-size "$rootkey" ./internal/builtin/ \
 'len(raw) > maxRootFile' 'false' '^TestRootFileSizeLimit$'
mutate root-file-truncate "$rootkey" ./internal/builtin/ \
 'maxRootFile+1' 'maxRootFile' '^TestRootFileSizeLimit$'
mutate root-read-prefix-leak "$rootkey" ./internal/builtin/ \
 'return nil, errLocalKey // root read' 'return nil, err // root read' \
 '^TestRootReadFailureWipesPartial$'

mutate mtls-eku "$mtls" ./internal/mtls/... \
	'KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},' \
	'KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},' \
	'^TestRequireMTLS_RejectsNonClientAuthCertificate$'

mutate mtls-chain "$mtls" ./internal/mtls/... \
	'}); err != nil {' \
	'}); false && err != nil {' \
	'^TestRequireMTLS_ForgedOrgClaimFailsChainVerification$'

mutate mtls-backend-as-rejected "$mtls" ./internal/mtls/... \
	'if errors.Is(err, registry.ErrRunnerRejected) {' \
	'if true || errors.Is(err, registry.ErrRunnerRejected) {' \
	'^TestRequireMTLS_RegistryFailureClassification$'

mutate mtls-rejection-as-backend "$mtls" ./internal/mtls/... \
	'if errors.Is(err, registry.ErrRunnerRejected) {' \
	'if false && errors.Is(err, registry.ErrRunnerRejected) {' \
	'^TestRequireMTLS_RegistryFailureClassification$'

mutate mtls-wrapped-rejection "$mtls" ./internal/mtls/... \
	'if errors.Is(err, registry.ErrRunnerRejected) {' \
	'if err == registry.ErrRunnerRejected {' \
	'^TestRequireMTLS_RegistryFailureClassification$'

mutate mtls-registry-error-log "$mtls" ./internal/mtls/... \
	'logAuthFailure(r.Context(), logger, reason, requestID)' \
	'logAuthFailure(r.Context(), logger, err.Error(), requestID)' \
	'^TestRequireMTLS_RegistryFailureClassification$'

mutate reg-revoked "$registry" ./internal/registry/... \
	'if revoked || serial != certSerial {' \
	'if false || serial != certSerial {' \
	'^TestCheckActiveRejectsRevoked$'

# Keep the bind parameter used, so this mutant builds and removes only CAS.
mutate renew-serial-cas "$registry" ./internal/api/... \
 'AND cert_serial = $5' 'AND $5::text IS NOT NULL' \
 '^TestRenewRunner_ConcurrentAuthenticatedRequests$'

mutate registry-renew-serial-cas "$registry" ./internal/registry/... \
 'AND cert_serial = $5' 'AND $5::text IS NOT NULL' \
 '^TestUpdateCertConcurrentSameSerial$'

mutate reg-stale "$registry" ./internal/registry/... \
	'if revoked || serial != certSerial {' \
	'if revoked || false {' \
	'^TestCheckActiveRejectsStaleSerialAfterRenewal$'

mutate startup-root-validation cmd/keep-server/app/main.go ./cmd/keep-server/... \
 '}); err != nil {' \
 '}); false && err != nil {' '^TestServeValidatesPersistentRoot$'
mutate enroll-token-backend "$runnersapi" ./internal/api/... \
 'if !errors.Is(err, enrolltoken.ErrTokenRejected) { // enroll token backend' \
 'if false && !errors.Is(err, enrolltoken.ErrTokenRejected) { // enroll token backend' \
 '^TestEnrollRunner_BackendClassification$'
mutate enroll-issuer-backend "$runnersapi" ./internal/api/... \
 'writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID) // enroll issuer' \
 'writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID) // enroll issuer' \
 '^TestEnrollRunner_BackendClassification$'
mutate renew-issuer-backend "$runnersapi" ./internal/api/... \
 'writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID) // renew issuer' \
 'writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID) // renew issuer' \
 '^TestRenewRunner_BackendClassification$'
mutate renew-registry-backend "$runnersapi" ./internal/api/... \
 'if errors.Is(err, registry.ErrRunnerUnknown) { // renew registry' \
 'if true || errors.Is(err, registry.ErrRunnerUnknown) { // renew registry' \
 '^TestRenewRunner_BackendClassification$'
mutate revoke-registry-backend "$runnersapi" ./internal/api/... \
 'if errors.Is(err, registry.ErrRunnerUnknown) { // revoke registry' \
 'if true || errors.Is(err, registry.ErrRunnerUnknown) { // revoke registry' \
 '^TestRevokeRunner_BackendClassification$'

mutate registry-check-org "$registry" ./internal/registry/... \
 'SELECT revoked_at IS NOT NULL, cert_serial FROM runners WHERE id = $1 AND org_id = $2' \
 'SELECT revoked_at IS NOT NULL, cert_serial FROM runners WHERE id = $1 AND $2::uuid IS NOT NULL' \
 '^TestCheckActiveRejectsCrossOrg$'
mutate registry-update-org "$registry" ./internal/registry/... \
 'WHERE id = $3 AND org_id = $4' 'WHERE id = $3 AND $4::uuid IS NOT NULL' \
 '^TestUpdateCertRejectsCrossOrg$'
mutate registry-revoke-org "$registry" ./internal/registry/... \
 'WHERE id = $2 AND org_id = $3' 'WHERE id = $2 AND $3::uuid IS NOT NULL' \
 '^TestRevokeRefusesCrossOrg$'

mutate ca-lookup-backend "$mtls" ./internal/mtls/... \
 'return Principal{}, "backend", err // CA lookup' \
 'return Principal{}, "unknown_org", err // CA lookup' \
 '^TestRequireMTLS_CAFailureClassification$'
mutate ca-der-backend "$mtls" ./internal/mtls/... \
 'return Principal{}, "backend", err // CA DER' \
 'return Principal{}, "unknown_org", err // CA DER' \
 '^TestRequireMTLS_CAFailureClassification$'

mutate issue-result-json "$enrolltoken" ./internal/enrolltoken/... \
 'return nil, fmt.Errorf("enrolltoken: IssueResult must not be marshaled directly, call Response() first")' \
 'return []byte(fmt.Sprintf("%q", r.Token.Reveal())), nil' \
 '^TestIssueResultNeverLeaksThroughJSON$'

mutate root-required internal/builtin/local.go ./cmd/keep-server/... \
 'return nil, errLocalKey // persistent root required' \
 'return NewLocal(pool, keyID, []byte("*******************************!"), log, onEvent)' \
 '^TestRootKeyFileRequired$'
mutate root-nonzero internal/builtin/sealer/rootkey.go ./internal/builtin/sealer/... \
 'if nonzero == 0 {' 'if false {' '^TestRootKeyRejectsZero$'
mutate root-identity internal/builtin/sealer/sealer.go ./internal/builtin/orgpki/... \
 'if rec.RootKeyID != s.root.ID() {' 'if false {' '^TestExistingCARejectsDifferentRoot$'

mutate ca-public-context "$orgpki" ./internal/builtin/orgpki/... \
 'Version: "v2:" + hex.EncodeToString(certDER)' 'Version: "v2:"' \
 '^TestLookupAuthenticatesPublicMaterial/ca_cert_der$'
mutate sign-id-context "$orgpki" ./internal/builtin/orgpki/... \
 'hex.EncodeToString([]byte(keyID))' '"constant"' \
 '^TestLookupAuthenticatesPublicMaterial/sign_key_id$'
mutate sign-public-context "$orgpki" ./internal/builtin/orgpki/... \
 'hex.EncodeToString(pub)' '"constant"' \
 '^TestLookupAuthenticatesPublicMaterial/sign_pub_key$'

mutate tok-host "$enrolltoken" ./internal/enrolltoken/... \
	'if host != p.Host {' \
	'if false {' \
	'^TestRedeemRefusesWrongHost$'

mutate tok-policy "$enrolltoken" ./internal/enrolltoken/... \
	'if policy != p.PolicySHA256 {' \
	'if false {' \
	'^TestRedeemRefusesWrongPolicyHash$'

mutate tok-expiry "$enrolltoken" ./internal/enrolltoken/... \
	'if !expiresAt.After(time.Now()) {' \
	'if false {' \
	'^TestRedeemRefusesAfterExpiry$'

mutate tok-race "$enrolltoken" ./internal/enrolltoken/... \
	'UPDATE enroll_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL' \
	'UPDATE enroll_tokens SET used_at = $1 WHERE id = $2' \
	'^TestRedeemRaceGuardIsLoadBearing$'

mutate requiretls "$runnersapi" ./internal/api/... \
	'if r.TLS == nil {' \
	'if false {' \
	'^TestIssueEnrollToken_RequiresTLSListener$'

mutate https-runner "$runnerenroll" ./cmd/keep-runner/... \
	'if !strings.HasPrefix(*server, "https://") {' \
	'if false {' \
	'^TestEnrollRejectsNonHTTPSServer$'

mutate redir-runner "$runnerenroll" ./cmd/keep-runner/... \
	'CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },' \
	'CheckRedirect: nil,' \
	'^TestEnrollDoesNotFollowRedirectToPlainHTTP$'

mutate https-keep "$keeprunnercli" ./cmd/keep/... \
	'if !strings.HasPrefix(server, "https://") {' \
	'if false {' \
	'^TestRunnerEnrollTokenRejectsNonHTTPSServer$|^TestRunnerRevokeRejectsNonHTTPSServer$'

mutate redir-keep "$keeprunnercli" ./cmd/keep/... \
	'CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },' \
	'CheckRedirect: nil,' \
	'^TestRunnerEnrollTokenDoesNotFollowRedirectToPlainHTTP$'

# keep-server logs "listening" only after both sockets are bound: the line is
# the readiness signal tests and supervisors wait for. One mutant logs it
# before the runner socket exists, the other binds the plain listener
# somewhere other than the configured address.
keepserver=cmd/keep-server/app/main.go
mutate listen-log-before-bind "$keepserver" ./cmd/keep-server/... \
	'runner, err := net.Listen("tcp", tlsSrv.Addr)' \
	'logger.Info("keep-server listening"); runner, err := net.Listen("tcp", tlsSrv.Addr)' \
	'^TestListeningLogMeansSocketsAreBound$'
mutate listen-first-not-released "$keepserver" ./cmd/keep-server/... \
	'_ = plain.Close()' \
	'_ = 0' \
	'^TestServeBothBindFailureIsStaticAndReleasesFirstListener$'
mutate listen-failure-echoes-error "$keepserver" ./cmd/keep-server/... \
	'logger.Error("keep-server stopped", "error_class", "listen_failed")' \
	'logger.Error("keep-server stopped: "+err.Error(), "error_class", "listen_failed")' \
	'^TestServeBothBindFailureIsStaticAndReleasesFirstListener$'
mutate listen-wrong-address "$keepserver" ./cmd/keep-server/... \
	'plain, err := net.Listen("tcp", srv.Addr)' \
	'plain, err := net.Listen("tcp", "127.0.0.1:0")' \
	'^TestListeningLogMeansSocketsAreBound$'

# New delivery material and host assertions must be backed by behavioral
# failures, including all exposed trust lookup gates.
mutate delivery-public-key "$runnersapi" ./internal/api/... \
 'if err := registry.ValidateDeliveryPublicKey(req.HPKEPublicKey); err != nil {' \
 'if err := registry.ValidateDeliveryPublicKey(req.HPKEPublicKey); false && err != nil {' \
 '^TestEnrollBindsDeliveryTrustFromIssuer$'
mutate host-attrs-override "$runnersapi" ./internal/api/... \
 'dec.DisallowUnknownFields()' \
 '_ = dec' \
 '^TestEnrollBindsDeliveryTrustFromIssuer$'
mutate delivery-key-save internal/runner/credential.go ./internal/runner/... \
 'if c.DeliveryKey != nil {' \
 'if false && c.DeliveryKey != nil {' \
 '^TestDeliveryKeyRoundTripAndRedaction$'
mutate delivery-key-format internal/runner/credential.go ./internal/runner/... \
 'func (c Credential) Format(f fmt.State, verb rune) { _, _ = fmt.Fprint(f, c.String()) }' \
 'func (c Credential) Format(f fmt.State, verb rune) { _, _ = fmt.Fprint(f, fmt.Sprintf("%x", c.DeliveryKey.Bytes())) }' \
 '^TestDeliveryKeyRoundTripAndRedaction$'
mutate delivery-org-scope "$registry" ./internal/registry/... \
 'FROM runners WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL AND cert_not_after > now()' \
 'FROM runners WHERE id = $1 AND ($2::uuid IS NOT NULL) AND revoked_at IS NULL AND cert_not_after > now()' \
 '^TestDeliveryTrustIsOrgScopedAndImmutableOnRenewal$'
mutate delivery-revoked "$registry" ./internal/registry/... \
 'FROM runners WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL AND cert_not_after > now()' \
 'FROM runners WHERE id = $1 AND org_id = $2 AND (revoked_at IS NULL OR true) AND cert_not_after > now()' \
 '^TestDeliveryTrustRejectsRevokedRunnerAndUnknownAttrsForProd$'
mutate delivery-keyless "$registry" ./internal/registry/... \
 'if ValidateDeliveryPublicKey(public) != nil {' \
 'if false && ValidateDeliveryPublicKey(public) != nil {' \
 '^TestLegacyRunnerCannotReceiveDeliveryKey$'
mutate delivery-attrs-provenance internal/store/migrations/00013_runner_delivery_trust.sql ./internal/store/... \
 'attrs_source IS NOT NULL AND attrs_source = '\''enroll_token'\''' \
 'attrs_source = '\''enroll_token'\''' \
 '^TestRunnerDeliveryMigrationDowngradePreservesRunner$'

# Each required trust-state outcome has its own missing-write control.
mutate enroll-ok-audit "$runnersapi" ./internal/api/... \
 'committed, err = journal.AppendTx(r.Context(), tx, record) // enroll ok audit' \
 'committed, err = record, error(nil) // enroll ok audit' \
 '^TestRunnerAuditFourOutcomes$'
mutate renew-ok-audit "$runnersapi" ./internal/api/... \
 'committed, err = journal.AppendTx(r.Context(), tx, record) // renew ok audit' \
 'committed, err = record, error(nil) // renew ok audit' \
 '^TestRunnerAuditFourOutcomes$'
mutate enroll-denied-audit "$runnersapi" ./internal/api/... \
 'appendRunnerDenial(r.Context(), aud, logger, runnerTrustRecord(requestID, redeemed.OrgID, uuid.Nil, "", audit.ActionRunnerEnroll, audit.StatusFailed)) // enroll denied audit' \
 'if false { appendRunnerDenial(r.Context(), aud, logger, runnerTrustRecord(requestID, redeemed.OrgID, uuid.Nil, "", audit.ActionRunnerEnroll, audit.StatusFailed)) }' \
 '^TestRunnerAuditFourOutcomes$'
mutate renew-denied-audit "$runnersapi" ./internal/api/... \
 'appendRunnerDenial(ctx, aud, logger, runnerTrustRecord(requestID, principal.OrgID, principal.RunnerID, principal.Host, audit.ActionRunnerRenew, audit.StatusFailed)) // renew denied audit' \
 'if false { appendRunnerDenial(ctx, aud, logger, runnerTrustRecord(requestID, principal.OrgID, principal.RunnerID, principal.Host, audit.ActionRunnerRenew, audit.StatusFailed)) }' \
 '^TestRunnerAuditFourOutcomes$|^TestRenewRunner_ConcurrentAuthenticatedRequests$'

# Seed each response capture independently: a detector check alone does not
# prove all four request paths reach the leak assertion.
mutate enroll-ok-canary internal/api/runner_audit_test.go ./internal/api/... \
 'assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // enroll-ok canary' \
 '_, _ = rec.Body.WriteString(token); assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // enroll-ok canary' \
 '^TestRunnerAuditFourOutcomes$'
mutate enroll-denied-canary internal/api/runner_audit_test.go ./internal/api/... \
 'assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // enroll-denied canary' \
 '_, _ = rec.Body.WriteString(token); assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // enroll-denied canary' \
 '^TestRunnerAuditFourOutcomes$'
mutate renew-ok-canary internal/api/runner_audit_test.go ./internal/api/... \
 'assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // renew-ok canary' \
 '_, _ = rec.Body.WriteString(token); assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // renew-ok canary' \
 '^TestRunnerAuditFourOutcomes$'
mutate renew-denied-canary internal/api/runner_audit_test.go ./internal/api/... \
 'assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // renew-denied canary' \
 '_, _ = rec.Body.WriteString(token); assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // renew-denied canary' \
 '^TestRunnerAuditFourOutcomes$'

mutation_apply_only && exit "$fail"

# internal/runner/health is left out: its launchd/systemd integration tests
# are opt-in (KEEP_*_INTEGRATION) and SKIP by design; it is proved by
# check-health-mutations.sh.
#
# -p 1: cmd/keep-server carries audit_verify_test.go's testPool(), which does
# `DROP SCHEMA public CASCADE` mid-run (unrelated to this script, inherited
# from the audit package). With the default per-package parallelism, that
# schema reset races orgpki's/registry's/enrolltoken's tests reading the real
# tables from a different package binary running at the same time — the same
# class of failure check-no-silent-skip.sh's own -p 1 exists for.
if (cd "$root" && KEEP_DATABASE_URL="$KEEP_DATABASE_URL" go test -count=1 -p 1 -v \
	./internal/builtin/... ./internal/runner/ ./internal/runner/discover/... ./cmd/keep-server/... \
	./internal/mtls/... ./internal/registry/... ./internal/enrolltoken/... ./internal/api/... \
	./cmd/keep/... ./cmd/keep-runner/... \
	>"$work/baseline_out" 2>&1); then
	if grep -q -- '--- SKIP' "$work/baseline_out"; then
		echo "FAIL baseline: a real test SKIPped — that is not a proven pass"
		fail=1
	else
		echo "ok   baseline: tests green on the real code, zero SKIPs"
	fi
else
	echo "FAIL baseline: tests are red on the real code"
	# Print only top-level test identifiers, never assertion text or process
	# output: a deliberately broken leak guard may carry a canary there.
	sed -n 's/^--- FAIL: \(Test[A-Za-z0-9_]*\).*/FAIL baseline test: \1/p' "$work/baseline_out"
	# A flaky baseline is undiagnosable from test names alone. Only fixed,
	# value-free phrases are echoed (never the matching line).
	for phrase in 'did not report listening' 'connection refused' 'i/o timeout' 'context deadline exceeded' 'Client.Timeout exceeded' 'address already in use' 'too many open files'; do
		if grep -q -F -- "$phrase" "$work/baseline_out"; then
			echo "FAIL baseline hint: output contains \"$phrase\""
		fi
	done
	if grep -q 'panic: test timed out' "$work/baseline_out"; then
		echo "FAIL baseline: test process exceeded its deadline"
	fi
	fail=1
fi

exit $fail
