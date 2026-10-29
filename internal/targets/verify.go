//go:build unix

package targets

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/internal/carriers/meshkey"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// readFormat is how a carrier file stores the value Verify looks for.
type readFormat string

const (
	// formatJSON: Field is a dotted path of object keys; a segment may carry
	// one [name=value] selector that picks the single array element whose
	// string member `name` equals value, e.g. agents[name=sage].agent_key.
	formatJSON readFormat = "json"
	// formatEnv: Field is a variable name in NAME=value / export NAME=value lines.
	formatEnv readFormat = "env"
)

// readSpec locates ONE field of a carrier file (unexported: the only way in
// is VerifyCarrier). Only locator data: no value.
type readSpec struct {
	Format readFormat
	Path   string
	Field  string
}

// VerifyCarrier verifies a carrier of the closed Mesh agent key manifest
// (meshkey.Carrier.Member) that sits under one of roots, the absolute
// directories the runner is configured to read carriers from. The manifest
// fixes its file name, format and field shape; the roots fix where it may be,
// so a caller cannot use it as a fingerprint oracle over an arbitrary readable
// file. Both are enforced before any file is opened: an empty or unusable
// roots list refuses everything, a path is descended from the root without
// following any link, and an agent env file must sit directly in a root. Errors name
// the carrier by kind and the caller's ordinal id and never echo a path,
// directory, file name or field.
func VerifyCarrier(roots []string, ordinal int, c meshkey.Carrier, want string, fpKey fingerprint.Key) (VerifyResult, error) {
	res, err := verifyCarrier(roots, c, want, fpKey)
	if err != nil {
		return "", fmt.Errorf("%w [carrier %s #%d]", err, carrierKind(c), ordinal)
	}
	return res, nil
}

// carrierKind is the closed kind of a manifest member; the kind of anything
// else is caller input and is not printed.
func carrierKind(c meshkey.Carrier) string {
	if c.Member() {
		return string(c.Kind)
	}
	return "unknown"
}

func verifyCarrier(roots []string, c meshkey.Carrier, want string, fpKey fingerprint.Key) (VerifyResult, error) {
	if !c.Member() {
		return "", denied("carrier is not in the Mesh agent key manifest")
	}
	dirfd, base, absent, err := openUnderRoots(roots, c)
	if err != nil {
		return "", err
	}
	if absent {
		return VerifyAbsent, nil
	}
	defer func() { _ = unix.Close(dirfd) }()
	return verifyIn(dirfd, base, readSpec{Format: readFormat(c.Format), Path: c.Path, Field: c.Field}, want, fpKey)
}

// openUnderRoots finds the root c sits under and opens the carrier's
// directory by descending from the root's real path one component at a time
// with O_NOFOLLOW, so no link below the root is followed, checked or not, and
// a swap between check and use cannot lead outside. The carrier file itself is
// opened later, relative to the returned directory descriptor. absent is true
// when a directory on the way or the file is not there; the caller closes dirfd.
func openUnderRoots(roots []string, c meshkey.Carrier) (dirfd int, base string, absent bool, err error) {
	usable := 0
	for _, r := range roots {
		if !path.IsAbs(r) || path.Clean(r) != r || r == "/" {
			continue
		}
		usable++
		if !strings.HasPrefix(c.Path, r+"/") {
			continue
		}
		rel := strings.TrimPrefix(c.Path, r+"/")
		if c.Kind == meshkey.AgentEnv && strings.Contains(rel, "/") {
			continue // agent.env: <root>/<name>.env, no subdirectories
		}
		realRoot, rerr := filepath.EvalSymlinks(r)
		if rerr != nil || realRoot == "/" {
			continue
		}
		return descend(realRoot, rel)
	}
	if usable == 0 {
		return -1, "", false, denied("no carrier root is configured")
	}
	return -1, "", false, denied("carrier is outside the configured roots")
}

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// cleanComponent reports whether one path component is a plain name, not
// empty, "." or "..".
func cleanComponent(comp string) bool {
	return comp != "" && comp != "." && comp != ".."
}

func descend(realRoot, rel string) (int, string, bool, error) {
	comps := strings.Split(rel, "/")
	for _, comp := range comps {
		if !cleanComponent(comp) {
			return -1, "", false, denied("carrier path is not clean")
		}
	}
	fd, oerr := unix.Open(realRoot, dirFlags, 0)
	if oerr != nil {
		return -1, "", false, writeFailed("cannot open the carrier root: %v", oerr)
	}
	for _, comp := range comps[:len(comps)-1] {
		next, oerr := unix.Openat(fd, comp, dirFlags, 0)
		_ = unix.Close(fd)
		switch {
		case oerr == nil:
			fd = next
		case errors.Is(oerr, unix.ENOENT):
			return -1, "", true, nil
		case errors.Is(oerr, unix.ELOOP), errors.Is(oerr, unix.ENOTDIR):
			return -1, "", false, denied("carrier path crosses a symlink or a non-directory")
		default:
			return -1, "", false, writeFailed("cannot open the carrier directory: %v", oerr)
		}
	}
	base := comps[len(comps)-1]
	var st unix.Stat_t
	if serr := unix.Fstatat(fd, base, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
		_ = unix.Close(fd)
		if errors.Is(serr, unix.ENOENT) {
			return -1, "", true, nil
		}
		return -1, "", false, writeFailed("cannot stat the carrier: %v", serr)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = unix.Close(fd)
		return -1, "", false, denied("carrier is a symlink")
	}
	return fd, base, false, nil
}

// VerifyResult is the whole outcome of a verification: no value, no neighbour.
type VerifyResult string

const (
	VerifyMatch    VerifyResult = "match"
	VerifyMismatch VerifyResult = "mismatch"
	VerifyAbsent   VerifyResult = "absent" // file or field not there
)

// verifySpec reports whether the carrier holds exactly the value whose
// fingerprint is want. It reads the file read-only, extracts only the named
// field, fingerprints it with pkg/fingerprint and returns the verdict. The
// file's other fields (frequently other services' secrets) are decoded in
// memory but never selected, compared, logged or returned; errors carry the
// class of failure, never content and never the locator. A symlink as the final path component,
// a non-regular file or a relative path is refused (links in parent
// directories are followed: Verify only reads); the target is not required to sit in a
// runner-private directory because Verify never writes.
func verifySpec(spec readSpec, want string, fpKey fingerprint.Key) (VerifyResult, error) {
	if !path.IsAbs(spec.Path) || path.Clean(spec.Path) != spec.Path || spec.Path == "/" {
		return "", denied("path is not a clean, non-root absolute path")
	}
	return verifyIn(unix.AT_FDCWD, spec.Path, spec, want, fpKey)
}

// verifyIn reads the carrier named name relative to dirfd (an absolute name
// when dirfd is AT_FDCWD).
func verifyIn(dirfd int, name string, spec readSpec, want string, fpKey fingerprint.Key) (VerifyResult, error) {
	if !fingerprint.Valid(want) {
		return "", writeFailed("expected fingerprint is not a well-formed fingerprint")
	}
	if spec.Format != formatJSON && spec.Format != formatEnv {
		return "", writeFailed("unknown carrier format")
	}
	content, exists, err := readCarrier(dirfd, name)
	if err != nil {
		return "", err
	}
	if !exists {
		return VerifyAbsent, nil
	}
	defer wipe(content)

	var val []byte
	var found bool
	switch spec.Format {
	case formatJSON:
		val, found, err = extractJSON(content, spec.Field)
	default:
		val, found, err = extractEnv(content, spec.Field)
	}
	if err != nil {
		return "", err
	}
	if !found {
		return VerifyAbsent, nil
	}
	defer wipe(val)

	sv := secret.New(val) // New copies: the copy is wiped too
	defer sv.Wipe()
	got, err := computeFingerprint(fpKey, sv)
	if err != nil {
		return "", writeFailed("compute fingerprint: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
		return VerifyMatch, nil
	}
	return VerifyMismatch, nil
}

// openCarrier is the one place Verify opens a file; tests count the calls.
var openCarrier = unix.Openat

func readCarrier(dirfd int, p string) (content []byte, exists bool, err error) {
	fd, oerr := openCarrier(dirfd, p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if oerr != nil {
		switch {
		case errors.Is(oerr, unix.ENOENT):
			return nil, false, nil
		case errors.Is(oerr, unix.ELOOP):
			return nil, false, denied("carrier is a symlink")
		}
		return nil, false, writeFailed("open carrier: %v", oerr)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, false, writeFailed("stat carrier: %v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, false, denied("carrier is not a regular file")
	}
	if st.Nlink != 1 {
		return nil, false, denied("carrier has more than one hard link")
	}
	if st.Size > maxTargetSize {
		return nil, false, writeFailed("carrier is too large")
	}
	b, err := readAllFD(fd, st.Size)
	if err != nil {
		return nil, false, writeFailed("read carrier: %v", err)
	}
	return b, true, nil
}

// selector is one parsed path segment.
type selector struct {
	key, matchKey, matchVal string
	pick                    bool
}

func parseSelectors(field string) ([]selector, error) {
	if field == "" {
		return nil, writeFailed("empty field selector")
	}
	var out []selector
	for _, seg := range strings.Split(field, ".") {
		s := selector{key: seg}
		if i := strings.IndexByte(seg, '['); i >= 0 {
			if !strings.HasSuffix(seg, "]") {
				return nil, writeFailed("malformed field selector")
			}
			inner := seg[i+1 : len(seg)-1]
			k, v, ok := strings.Cut(inner, "=")
			if !ok || k == "" || v == "" || strings.ContainsAny(inner, "[]") {
				return nil, writeFailed("malformed field selector")
			}
			s = selector{key: seg[:i], matchKey: k, matchVal: v, pick: true}
		}
		if s.key == "" {
			return nil, writeFailed("malformed field selector")
		}
		out = append(out, s)
	}
	return out, nil
}

// extractJSON returns a copy of the one string the selector names. Everything
// else in the document stays in the decoded tree and is dropped with it.
func extractJSON(content []byte, field string) ([]byte, bool, error) {
	sels, err := parseSelectors(field)
	if err != nil {
		return nil, false, err
	}
	doc, err := decodeObject(content)
	if err != nil {
		// decodeObject names the byte offset of a syntax error; in a file of
		// other services' secrets that locates a byte of a neighbour.
		return nil, false, writeFailed("carrier is not a valid JSON object")
	}
	var cur any = doc
	for _, s := range sels {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false, writeFailed("JSON on the way to the field is not an object")
		}
		next, present := obj[s.key]
		if !present {
			return nil, false, nil
		}
		if s.pick {
			arr, ok := next.([]any)
			if !ok {
				return nil, false, writeFailed("JSON member of the field path is not an array")
			}
			var hit any
			n := 0
			for _, el := range arr {
				m, ok := el.(map[string]any)
				if !ok {
					continue
				}
				if name, ok := m[s.matchKey].(string); ok && name == s.matchVal {
					hit = m
					n++
				}
			}
			switch n {
			case 0:
				return nil, false, nil
			case 1:
				next = hit
			default:
				return nil, false, writeFailed("selector matches more than one element")
			}
		}
		cur = next
	}
	str, ok := cur.(string)
	if !ok {
		return nil, false, writeFailed("JSON field is not a string")
	}
	return []byte(str), true, nil
}

// extractEnv returns the value of the LAST assignment to name, as a shell
// reading the file would see it, in the forms NAME=v, export NAME=v, with
// bare, 'single' or "double" quoting and no expansion. Anything it cannot
// read with certainty (command substitution, $ expansion, a quote left open)
// is refused, not guessed.
func extractEnv(content []byte, name string) ([]byte, bool, error) {
	if name == "" || strings.ContainsAny(name, "=\n\r \t") {
		return nil, false, writeFailed("malformed variable name")
	}
	var val []byte
	found := false
	for _, line := range bytes.Split(content, []byte("\n")) {
		l := bytes.TrimLeft(line, " \t")
		l = bytes.TrimSuffix(l, []byte("\r"))
		if rest, ok := bytes.CutPrefix(l, []byte("export")); ok && len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
			l = bytes.TrimLeft(rest, " \t")
		}
		rest, ok := bytes.CutPrefix(l, []byte(name+"="))
		if !ok {
			continue
		}
		v, err := envValue(rest)
		if err != nil {
			wipe(val)
			return nil, false, err
		}
		wipe(val)
		val, found = v, true
	}
	return val, found, nil
}

func envValue(raw []byte) ([]byte, error) {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		switch c := raw[i]; c {
		case '\'', '"':
			j := bytes.IndexByte(raw[i+1:], c)
			if j < 0 {
				wipe(out)
				return nil, writeFailed("carrier has an unterminated quote on the assignment")
			}
			chunk := raw[i+1 : i+1+j]
			if c == '"' && bytes.ContainsAny(chunk, "$`\\") {
				wipe(out)
				return nil, writeFailed("carrier assignment needs shell expansion; refused")
			}
			out = append(out, chunk...)
			i += j + 2
		case '$', '`', '\\', '(', ')', ';', '&', '|', '<', '>':
			wipe(out)
			return nil, writeFailed("carrier assignment needs shell expansion; refused")
		case ' ', '\t':
			// A word ends at blanks; what follows is a comment or another
			// word. A '#' inside a word is part of the value.
			return out, nil
		default:
			out = append(out, c)
			i++
		}
	}
	return out, nil
}
