// Package discover inventories only explicitly permitted local carrier files.
// It returns names, lengths and keyed fingerprints, never secret values.
package discover

import "errors"

type Kind string

const (
	EnvFile      Kind = "env-file"
	LaunchdPlist Kind = "launchd-plist"
	SystemdUnit  Kind = "systemd-unit"
	Credential   Kind = "credential"
	MCPConfig    Kind = "mcp-config"
)

// Rule comes from trusted local host policy. Names is an exact allowlist;
// names parsed out of untrusted files cannot become output metadata.
// Credential files require exactly one policy-supplied name.
type Rule struct {
	Glob  string
	Kind  Kind
	Names []string
}

// Policy grants reads beneath an absolute, non-symlinked root. Globs are
// relative, finite-depth filepath.Match patterns; recursive ** is refused.
type Policy struct {
	Root     string
	Rules    []Rule
	MaxBytes int64
	MaxFiles int
	// TrustedUIDs are writer identities authenticated by the local host policy.
	// Never include an untrusted caller. Every admitted path owner must be listed.
	TrustedUIDs []uint32
}

type Finding struct {
	Path        string
	Name        string
	Fingerprint string
	Len         int
}

// KnownCarrier is trusted registry metadata, independent of registry storage.
// Fingerprint must use the same tenant key as the findings being compared.
type KnownCarrier struct {
	Path        string
	Name        string
	Fingerprint string
	Active      bool
}

type Verdict string

const (
	Match       Verdict = "match"
	Stale       Verdict = "stale"
	Sprawl      Verdict = "sprawl"
	UnknownFind Verdict = "unknown_find"
)

type Observation struct {
	Finding Finding
	Verdict Verdict
}

var (
	ErrPolicy      = errors.New("discover: invalid local policy")
	ErrRead        = errors.New("discover: carrier unavailable or unsafe")
	ErrSize        = errors.New("discover: carrier exceeds size limit")
	ErrParse       = errors.New("discover: unsupported or malformed carrier")
	ErrFingerprint = errors.New("discover: fingerprint rejected")
	ErrCanceled    = errors.New("discover: scan canceled")
)
