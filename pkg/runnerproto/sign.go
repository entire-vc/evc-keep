package runnerproto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// SignedJob is what travels from the server to the runner. Payload is the
// canonical encoding of the job; the runner verifies Sig over exactly these
// bytes before it reads any of them.
type SignedJob struct {
	KeyID   string `json:"key_id"`
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
}

// Signer signs jobs on the server.
type Signer struct {
	KeyID string
	Key   ed25519.PrivateKey
}

// Enrollment identifiers predate job delivery and include an underscore.
// Keep their pinned spelling; changing it would invalidate the sealed key context.
var signingKeyIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Sign validates, encodes and signs j.
func (s Signer) Sign(j Job) (SignedJob, error) {
	if !signingKeyIDRe.MatchString(s.KeyID) || len(s.Key) != ed25519.PrivateKeySize {
		return SignedJob{}, errors.New("runnerproto: signer key is not set")
	}
	p, err := EncodeJob(j)
	if err != nil {
		return SignedJob{}, err
	}
	return SignedJob{KeyID: s.KeyID, Payload: p, Sig: ed25519.Sign(s.Key, p)}, nil
}

// Rejections. Each is a distinct error class in the runner's result.
var (
	ErrSignature   = errors.New("runnerproto: job signature is not valid")
	ErrWrongRunner = errors.New("runnerproto: job is for another org or runner")
	ErrExpired     = errors.New("runnerproto: job is outside its time window")
	ErrReplay      = errors.New("runnerproto: job id was already used")
)

// Identity is the runner's own org and runner id, taken from its enrollment
// certificate, never from a job.
type Identity struct {
	OrgID    string
	RunnerID string
}

// TrustedKeys are the server signing keys the runner pinned at enrollment,
// by key id.
type TrustedKeys map[string]ed25519.PublicKey

// VerifyJob is the runner's gate for an incoming job. The order matters:
// nothing in the payload is parsed before the signature holds, and the
// replay journal is written last, so a job rejected for any other reason
// does not burn its id.
func VerifyJob(sj SignedJob, keys TrustedKeys, me Identity, now time.Time, journal Journal) (Job, error) {
	pub, ok := keys[sj.KeyID]
	if !ok || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, sj.Payload, sj.Sig) {
		return Job{}, ErrSignature
	}
	j, err := DecodeJob(sj.Payload)
	if err != nil {
		return Job{}, err
	}
	if j.OrgID != me.OrgID || j.RunnerID != me.RunnerID {
		return Job{}, ErrWrongRunner
	}
	if now.Add(ClockSkew).Before(j.IssuedAt) || !now.Before(j.NotAfter.Add(ClockSkew)) {
		return Job{}, ErrExpired
	}
	if journal == nil {
		return Job{}, fmt.Errorf("%w: no replay journal", ErrReplay)
	}
	if err := journal.Claim(j.JobID, j.NotAfter, now); err != nil {
		return Job{}, err
	}
	return j, nil
}
