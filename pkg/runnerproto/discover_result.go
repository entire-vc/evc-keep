package runnerproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

// ErrClassDiscoveryFailed is the one outward class of a failed scan. A read,
// parse or size failure all collapse into it: literal syntax rejection would
// otherwise reveal one bit about a value (docs/carrier-discovery.md). It is
// valid on a DiscoverResult only, never on a Result.
const ErrClassDiscoveryFailed ErrorClass = "discovery_failed"

// MaxDiscoverFindings bounds one report.
const MaxDiscoverFindings = 4096

// maxFindingLen bounds a reported value length.
const maxFindingLen = 1 << 20

// DiscoverFinding is one carrier the runner found: where, which variable,
// the keyed fingerprint and the length. Path is absolute (policy root plus
// the relative path) so the server can compare it with a carrier's
// target.path. No value, no digest other than the keyed fingerprint.
type DiscoverFinding struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Len         int    `json:"len"`
}

// DiscoverResult is everything a runner reports about a discover job, and it
// is closed. It is a separate type: Result stays as it is. After a failed
// scan Findings is empty and OK is false: a failed read proves nothing about
// absence, so the server never compares such a report.
type DiscoverResult struct {
	OK         bool              `json:"ok"`
	ErrorClass ErrorClass        `json:"error_class,omitempty"`
	Findings   []DiscoverFinding `json:"findings"`
}

// ErrInvalidDiscoverResult is returned for a report outside the contract.
var ErrInvalidDiscoverResult = errors.New("runnerproto: invalid discover result")

var (
	discoverKeys = map[string]bool{"ok": true, "error_class": true, "findings": true}
	findingKeys  = map[string]bool{"path": true, "name": true, "fingerprint": true, "len": true}
)

// discoverFailureClasses are the classes a failed discover report may carry:
// the one scan class, plus the rejections that happen before a scan starts.
// The deploy-only classes (fingerprint_mismatch, value_unavailable, ...) mean
// nothing here and are refused, so a runner has one way to say each thing.
var discoverFailureClasses = map[ErrorClass]bool{
	ErrClassDiscoveryFailed: true, ErrClassPolicyDenied: true, ErrClassInvalidJob: true,
	ErrClassRateLimited: true, ErrClassInternal: true, ErrClassSignature: true,
	ErrClassExpired: true, ErrClassReplay: true, ErrClassWrongRunner: true,
}

// Validate checks r against the contract.
func (r DiscoverResult) Validate() error {
	// A nil slice marshals to findings:null, which the decoder refuses;
	// the report must say "no findings" with an empty array.
	if r.Findings == nil {
		return ErrInvalidDiscoverResult
	}
	if r.OK {
		if r.ErrorClass != "" || len(r.Findings) > MaxDiscoverFindings {
			return ErrInvalidDiscoverResult
		}
	} else if !discoverFailureClasses[r.ErrorClass] || len(r.Findings) != 0 {
		return ErrInvalidDiscoverResult
	}
	type key struct{ path, name string }
	seen := make(map[key]bool, len(r.Findings))
	for _, f := range r.Findings {
		if err := f.validate(); err != nil {
			return err
		}
		// One finding per path and name: two with different fingerprints
		// would be ambiguous for the server's comparison.
		if k := (key{f.Path, f.Name}); seen[k] {
			return ErrInvalidDiscoverResult
		} else {
			seen[k] = true
		}
	}
	return nil
}

func (f DiscoverFinding) validate() error {
	if ValidatePath(f.Path) != nil || !utf8.ValidString(f.Path) {
		return ErrInvalidDiscoverResult
	}
	for _, c := range f.Path {
		if !unicode.IsPrint(c) {
			return ErrInvalidDiscoverResult
		}
	}
	switch {
	case !envFieldRe.MatchString(f.Name) && !nameRe.MatchString(f.Name):
		return ErrInvalidDiscoverResult
	case !fingerprint.Valid(f.Fingerprint):
		return ErrInvalidDiscoverResult
	case f.Len < 0 || f.Len > maxFindingLen:
		return ErrInvalidDiscoverResult
	}
	return nil
}

// DecodeDiscoverResult is how the server reads a report: unknown fields,
// case-variant or duplicate keys, trailing data and anything Validate
// rejects are refused.
func DecodeDiscoverResult(b []byte) (DiscoverResult, error) {
	if !exactKeys(b, discoverKeys) {
		return DiscoverResult{}, ErrInvalidDiscoverResult
	}
	top, ok := requiredFields(b, "ok", "findings")
	if !ok {
		return DiscoverResult{}, ErrInvalidDiscoverResult
	}
	var findings []json.RawMessage
	// findings must be a JSON array; null was refused by requiredFields.
	if json.Unmarshal(top["findings"], &findings) != nil {
		return DiscoverResult{}, ErrInvalidDiscoverResult
	}
	for _, f := range findings {
		if !exactKeys(f, findingKeys) {
			return DiscoverResult{}, ErrInvalidDiscoverResult
		}
		if _, ok := requiredFields(f, "path", "name", "fingerprint", "len"); !ok {
			return DiscoverResult{}, ErrInvalidDiscoverResult
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r DiscoverResult
	if err := dec.Decode(&r); err != nil || !atEOF(dec) {
		return DiscoverResult{}, ErrInvalidDiscoverResult
	}
	if err := r.Validate(); err != nil {
		return DiscoverResult{}, err
	}
	return r, nil
}

// requiredFields returns the members of the object b and reports whether
// every named key is present and not null. json.Unmarshal turns a missing or
// null member into its zero value (len 0, ok false), which would make an
// unknown length or verdict look like a real one.
func requiredFields(b []byte, names ...string) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	for _, n := range names {
		if v, ok := m[n]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, false
		}
	}
	return m, true
}
