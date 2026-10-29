package discover

import (
	"context"
	"crypto/subtle"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Scan is all-or-nothing. A read/parse failure returns no partial inventory:
// an incomplete scan must never be mistaken for evidence of a lost carrier.
// The caller owns the tenant key and must authenticate its tenant binding.
func Scan(ctx context.Context, p Policy, key fingerprint.Key) ([]Finding, error) {
	if err := validatePolicy(p); err != nil {
		return nil, err
	}
	if _, err := fingerprint.Compute(key, secret.Value{}); err != nil {
		return nil, ErrFingerprint
	}
	root, err := openRoot(p.Root, p.TrustedUIDs)
	if err != nil {
		return nil, ErrRead
	}
	defer func() { _ = root.Close() }()
	out := []Finding{}
	seen := map[string]bool{}
	files := 0
	for _, rule := range p.Rules {
		if ctx.Err() != nil {
			return nil, ErrCanceled
		}
		paths, err := expand(ctx, root, rule.Glob, p.MaxFiles, p.TrustedUIDs)
		if err != nil {
			return nil, err
		}
		files += len(paths)
		if files > p.MaxFiles {
			return nil, ErrPolicy
		}
		for _, path := range paths {
			if ctx.Err() != nil {
				return nil, ErrCanceled
			}
			f, err := openRelative(root, path, false, p.TrustedUIDs)
			if errors.Is(err, errAbsent) {
				continue
			}
			if err != nil {
				return nil, ErrRead
			}
			data, err := readBounded(f, p.MaxBytes)
			_ = f.Close()
			if err != nil {
				return nil, err
			}
			parsed, err := parseCarrier(data, rule, path, key)
			wipe(data)
			if err != nil {
				return nil, err
			}
			for _, finding := range parsed {
				id := finding.Path + "\x00" + finding.Name
				if seen[id] {
					return nil, ErrPolicy
				}
				seen[id] = true
				out = append(out, finding)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func validatePolicy(p Policy) error {
	if len(p.TrustedUIDs) == 0 || len(p.TrustedUIDs) > 32 {
		return ErrPolicy
	}
	if !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) == string(filepath.Separator) || len(p.Rules) == 0 || len(p.Rules) > 256 || p.MaxBytes <= 0 || p.MaxBytes > 16<<20 || p.MaxFiles <= 0 || p.MaxFiles > 4096 {
		return ErrPolicy
	}
	for _, r := range p.Rules {
		if !safeRelative(r.Glob) || strings.Contains(r.Glob, "**") || strings.Contains(r.Glob, "~") || len(strings.Split(r.Glob, "/")) > 16 || len(r.Names) == 0 || len(r.Names) > 256 {
			return ErrPolicy
		}
		if _, err := filepath.Match(r.Glob, ""); err != nil {
			return ErrPolicy
		}
		switch r.Kind {
		case EnvFile, LaunchdPlist, SystemdUnit, MCPConfig:
		case Credential:
			if len(r.Names) != 1 {
				return ErrPolicy
			}
		default:
			return ErrPolicy
		}
		seen := map[string]bool{}
		for _, name := range r.Names {
			if !validName(name) || seen[name] {
				return ErrPolicy
			}
			seen[name] = true
		}
	}
	return nil
}

func safeRelative(path string) bool {
	if !utf8.ValidString(path) {
		return false
	}
	for _, r := range path {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	if path == "" || filepath.IsAbs(path) || strings.ContainsRune(path, 0) || strings.Contains(path, "\\") {
		return false
	}
	for _, p := range strings.Split(path, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for i, c := range []byte(name) {
		allowed := c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9'
		if !allowed {
			return false
		}
	}
	return true
}

// appendWiped clears an old backing array before growing a value buffer.
func appendWiped(dst, src []byte) []byte {
	if len(dst)+len(src) > cap(dst) {
		size := cap(dst) * 2
		if size < len(dst)+len(src) {
			size = len(dst) + len(src)
		}
		next := make([]byte, len(dst), size)
		copy(next, dst)
		wipe(dst)
		dst = next
	}
	return append(dst, src...)
}

var errAbsent = errors.New("discover: permitted path absent")

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func finding(path, name string, raw []byte, key fingerprint.Key) (Finding, error) {
	v := secret.New(raw)
	defer v.Wipe()
	fp, err := fingerprint.Compute(key, v)
	if err != nil || fp == "" {
		return Finding{}, ErrFingerprint
	}
	return Finding{Path: path, Name: name, Fingerprint: fp, Len: v.Len()}, nil
}

// Compare never issues, revokes or recommends reissuing a secret. Missing
// active known carriers require finding the carrier; inactive absences are ignored.
// Call it only after a successful complete Scan, never with partial results.
// The caller must authenticate the expected tenant key independently of the
// submitted findings and registry; every fingerprint must carry that key ID.
func Compare(key fingerprint.Key, findings []Finding, known []KnownCarrier) ([]Observation, error) {
	out := make([]Observation, 0, len(findings)+len(known))
	byID := map[string]KnownCarrier{}
	seen := map[string]bool{}
	if _, err := fingerprint.Compute(key, secret.Value{}); err != nil {
		return nil, ErrFingerprint
	}
	keyID := key.ID()
	check := func(fp string) bool {
		p, err := fingerprint.Parse(fp)
		if err != nil {
			return false
		}
		return p.KeyID == keyID
	}
	for _, k := range known {
		id := k.Path + "\x00" + k.Name
		if !safeRelative(k.Path) || !validName(k.Name) || !check(k.Fingerprint) {
			return nil, ErrFingerprint
		}
		if _, ok := byID[id]; ok {
			return nil, ErrPolicy
		}
		byID[id] = k
	}
	for _, f := range findings {
		id := f.Path + "\x00" + f.Name
		if !safeRelative(f.Path) || !validName(f.Name) || f.Len < 0 || !check(f.Fingerprint) {
			return nil, ErrFingerprint
		}
		if seen[id] {
			return nil, ErrPolicy
		}
		seen[id] = true
		verdict := Sprawl
		if k, ok := byID[id]; ok {
			verdict = Stale
			if subtle.ConstantTimeCompare([]byte(f.Fingerprint), []byte(k.Fingerprint)) == 1 {
				verdict = Match
			}
		}
		out = append(out, Observation{Finding: f, Verdict: verdict})
	}
	for _, k := range known {
		if k.Active && !seen[k.Path+"\x00"+k.Name] {
			out = append(out, Observation{Finding: Finding{Path: k.Path, Name: k.Name}, Verdict: UnknownFind})
		}
	}
	return out, nil
}
