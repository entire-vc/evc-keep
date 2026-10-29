package runnerproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

// Result is everything a runner reports about a job, and it is closed: the
// fields below, as in threat model 4.3, and nothing else. A test walks the
// type with reflection and fails on any added field. The job id travels in
// the request path, not here.
type Result struct {
	OK          bool         `json:"ok"`
	Fingerprint string       `json:"fingerprint,omitempty"`
	Version     string       `json:"version,omitempty"`
	Healthcheck *Healthcheck `json:"healthcheck,omitempty"`
	ErrorClass  ErrorClass   `json:"error_class,omitempty"`
}

// Healthcheck is the consumer's state after the job.
type Healthcheck struct {
	Status     HealthStatus `json:"status"`
	Kind       HealthKind   `json:"kind"`
	DurationMs int64        `json:"duration_ms"`
	CheckedAt  time.Time    `json:"checked_at"`
}

// HealthStatus is a closed list.
type HealthStatus string

const (
	HealthOK      HealthStatus = "ok"
	HealthFailed  HealthStatus = "failed"
	HealthSkipped HealthStatus = "skipped"
)

// HealthKind is the closed list of healthcheck kinds a host policy may run —
// never an arbitrary command, which would bypass exec_with_secret. Empty is
// valid only alongside HealthSkipped: no consumer was configured, so no kind
// of check ever ran.
type HealthKind string

const (
	// HealthKindUnitActive: the consumer stays up for the configured hold
	// time after restart.
	HealthKindUnitActive HealthKind = "unit-active"
	// HealthKindHTTP: a GET to a loopback-only address, an expected status
	// code and a required body marker, within a timeout. The response body
	// itself never leaves the check — see ClassOf/Result's own contract.
	HealthKindHTTP HealthKind = "http"
)

// ErrorClass is a closed list. A class names what went wrong, never a
// value, path content or provider output.
type ErrorClass string

const (
	ErrClassSignature           ErrorClass = "signature_invalid"
	ErrClassWrongRunner         ErrorClass = "wrong_runner"
	ErrClassExpired             ErrorClass = "job_expired"
	ErrClassReplay              ErrorClass = "job_replayed"
	ErrClassInvalidJob          ErrorClass = "job_invalid"
	ErrClassPolicyDenied        ErrorClass = "policy_denied"
	ErrClassRateLimited         ErrorClass = "rate_limited"
	ErrClassValueUnavailable    ErrorClass = "value_unavailable"
	ErrClassFingerprintMismatch ErrorClass = "fingerprint_mismatch"
	ErrClassVersionMismatch     ErrorClass = "version_mismatch"
	ErrClassTargetWrite         ErrorClass = "target_write_failed"
	ErrClassHealthcheck         ErrorClass = "healthcheck_failed"
	ErrClassProvider            ErrorClass = "provider_failed"
	ErrClassInternal            ErrorClass = "internal"
)

var errorClasses = map[ErrorClass]bool{
	ErrClassSignature: true, ErrClassWrongRunner: true, ErrClassExpired: true,
	ErrClassReplay: true, ErrClassInvalidJob: true, ErrClassPolicyDenied: true,
	ErrClassRateLimited: true, ErrClassValueUnavailable: true,
	ErrClassFingerprintMismatch: true, ErrClassVersionMismatch: true,
	ErrClassTargetWrite: true, ErrClassHealthcheck: true,
	ErrClassProvider: true, ErrClassInternal: true,
}

// Valid reports whether c is one of the closed classes. The empty class is
// not valid: callers that allow "no class" test for it first.
func (c ErrorClass) Valid() bool { return errorClasses[c] }

// ClassOf maps a rejection from this package to its error class.
func ClassOf(err error) ErrorClass {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrSignature):
		return ErrClassSignature
	case errors.Is(err, ErrWrongRunner):
		return ErrClassWrongRunner
	case errors.Is(err, ErrExpired):
		return ErrClassExpired
	case errors.Is(err, ErrReplay):
		return ErrClassReplay
	case errors.Is(err, ErrInvalidJob):
		return ErrClassInvalidJob
	case errors.Is(err, ErrPolicy):
		return ErrClassPolicyDenied
	}
	return ErrClassInternal
}

var (
	resultKeys      = map[string]bool{"ok": true, "fingerprint": true, "version": true, "healthcheck": true, "error_class": true}
	healthcheckKeys = map[string]bool{"status": true, "kind": true, "duration_ms": true, "checked_at": true}
)

// exactKeys reports whether b is a JSON object whose keys are all in
// allowed, spelled exactly, each once, with healthcheck checked likewise.
func exactKeys(b []byte, allowed map[string]bool) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		k, ok := t.(string)
		if err != nil || !ok || !allowed[k] || seen[k] {
			return false
		}
		seen[k] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return false
		}
		if k == "healthcheck" && string(raw) != "null" && !exactKeys(raw, healthcheckKeys) {
			return false
		}
	}
	return true
}

// atEOF reports whether dec has nothing left but whitespace. dec.More is not
// enough: it looks for another element of the enclosing array or object, so
// at the top level a stray "]" or "}" after the value passes it.
func atEOF(dec *json.Decoder) bool {
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

// ErrInvalidResult is returned for a result outside the contract.
var ErrInvalidResult = errors.New("runnerproto: invalid result")

// Validate checks r against the contract.
func (r Result) Validate() error {
	switch {
	case r.OK && r.ErrorClass != "":
		return ErrInvalidResult
	case !r.OK && !errorClasses[r.ErrorClass]:
		return ErrInvalidResult
	case r.Fingerprint != "" && !fingerprint.Valid(r.Fingerprint):
		return ErrInvalidResult
	case r.Version != "" && !versionRe.MatchString(r.Version):
		return ErrInvalidResult
	}
	if h := r.Healthcheck; h != nil {
		switch h.Status {
		case HealthOK, HealthFailed, HealthSkipped:
		default:
			return ErrInvalidResult
		}
		switch h.Kind {
		case HealthKindUnitActive, HealthKindHTTP:
		case "":
			if h.Status != HealthSkipped {
				return ErrInvalidResult
			}
		default:
			return ErrInvalidResult
		}
		if h.DurationMs < 0 {
			return ErrInvalidResult
		}
	}
	return nil
}

// DecodeResult is how the server reads a result: unknown fields, trailing
// data and anything Validate rejects are refused, so a runner, compromised
// or not, cannot smuggle a field past the closed list.
func DecodeResult(b []byte) (Result, error) {
	// encoding/json matches keys case-insensitively and lets a later
	// duplicate win; neither is part of the contract.
	if !exactKeys(b, resultKeys) {
		return Result{}, ErrInvalidResult
	}
	// exactKeys already refused unknown keys, so no DisallowUnknownFields.
	dec := json.NewDecoder(bytes.NewReader(b))
	var r Result
	if err := dec.Decode(&r); err != nil {
		return Result{}, ErrInvalidResult
	}
	if !atEOF(dec) {
		return Result{}, ErrInvalidResult
	}
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	return r, nil
}
