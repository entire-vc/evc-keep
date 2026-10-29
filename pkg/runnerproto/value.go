package runnerproto

import (
	"errors"
	"time"
)

// HPKE suite for value delivery (RFC 9180, base mode): DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. The runner's X25519 public
// key is registered at enrollment; the server never takes it from a
// request.
const (
	HPKEKEM  uint16 = 0x0020
	HPKEKDF  uint16 = 0x0001
	HPKEAEAD uint16 = 0x0003
)

// valueDomain opens the HPKE info string.
const valueDomain = "keep/value/v1\x00"

// ValueRequest is the runner's call for the value of a builtin secret. It
// names the job and nothing else: org and runner come from the mTLS
// certificate, the secret and version from the server's own record of the
// job. A runner cannot ask for a secret by name.
type ValueRequest struct {
	JobID string `json:"job_id"`
}

// ValueEnvelope is the server's answer: the value sealed with single-shot
// HPKE to the runner's key, Info(job) as the info string. Sealed is the
// encapsulated key followed by the ciphertext.
type ValueEnvelope struct {
	JobID                string `json:"job_id"`
	Sealed               []byte `json:"sealed"`
	SealedFingerprintKey []byte `json:"sealed_fingerprint_key"`
}

// FingerprintKeyInfo binds the separate fingerprint-key envelope to the
// complete value context. No envelope can serve both purposes.
func FingerprintKeyInfo(j Job) []byte {
	return append([]byte("keep/fingerprint-key/v1\x00"), Info(j)...)
}

// VerifyKeyInfo is the HPKE info string of the fingerprint key a verify job
// receives. It has its own domain, so that no envelope sealed for a deploy
// or exec job opens as a verify key or the other way round, and it binds the
// job's nonce and expiry on top of everything Info binds: an envelope is good
// for this one job, this runner and this window only.
func VerifyKeyInfo(j Job) []byte {
	var e encoder
	e.b.WriteString("keep/fingerprint-key/verify/v1\x00")
	e.b.Write(Info(j))
	e.field(tagNonce, j.Nonce)
	e.i64(tagIssuedAt, j.IssuedAt.Unix())
	e.i64(tagNotAfter, j.NotAfter.Unix())
	return e.b.Bytes()
}

// Info is the HPKE info string for the value of job j. It binds the
// ciphertext to this job, runner, secret (including scope and provider),
// version and fingerprint: an envelope captured for one job does not open
// as the value for another.
// After opening, the runner checks the value's fingerprint against
// j.ExpectedFingerprint before writing it anywhere.
func Info(j Job) []byte {
	var e encoder
	e.b.WriteString(valueDomain)
	e.str(tagJobID, j.JobID)
	e.str(tagOrgID, j.OrgID)
	e.str(tagRunnerID, j.RunnerID)
	e.str(tagStoreID, j.Secret.StoreID)
	e.str(tagSecretName, j.Secret.Name)
	e.str(tagExpectedVersion, j.ExpectedVersion)
	e.str(tagExpectedFingerprint, j.ExpectedFingerprint)
	// Append the bindings required before the first production delivery.
	// Keep the historical prefix and tag numbers stable; there is no fallback
	// to the old context, which did not bind scope or provider.
	e.str(tagSecretScope, j.Secret.Scope)
	e.str(tagProvider, j.Secret.Provider)
	return e.b.Bytes()
}

// Release refusals. The server answers each the same way on the wire (not
// found), so a runner cannot probe which jobs exist.
var (
	ErrNotReleasable = errors.New("runnerproto: this job does not release a value")
	ErrReleased      = errors.New("runnerproto: value for this job was already released")
)

// CheckRelease is the server's gate before it unseals a builtin value for a
// runner (threat model 2.3 E: builtin gives a runner only the secrets bound
// to its own jobs). job is the server's own record, looked up by
// ValueRequest.JobID; peer is the identity from the client certificate.
// released reports whether this job's value has already been handed out;
// the caller records the release atomically with the check.
func CheckRelease(job Job, peer Identity, now time.Time, released bool) error {
	switch {
	case job.OrgID != peer.OrgID || job.RunnerID != peer.RunnerID:
		return ErrWrongRunner
	case !job.NeedsValue() || job.Secret.Provider != ProviderBuiltin:
		return ErrNotReleasable
	case !now.Before(job.NotAfter) || now.Before(job.IssuedAt.Add(-ClockSkew)):
		return ErrExpired
	case released:
		return ErrReleased
	}
	return nil
}
