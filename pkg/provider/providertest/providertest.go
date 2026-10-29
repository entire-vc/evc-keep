// Package providertest is the conformance suite every Keep provider must
// pass. Use Run from a provider's tests:
//
//	func TestConformance(t *testing.T) {
//	    providertest.Run(t, func(log *slog.Logger) providertest.Harness {
//	        p := myprovider.New(testBackend(t), log)
//	        return providertest.Harness{Provider: p, SetUnavailable: p.testOutage}
//	    })
//	}
//
// Check returns the same verdicts as data, so the suite itself can be tested
// against deliberately broken providers (see broken_test.go): a check that has
// never been seen to fail is not a check.
package providertest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/entire-vc/evc-keep/internal/testutil/fdredirect"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Harness is one fresh, empty provider instance plus test controls.
type Harness struct {
	Provider provider.Provider
	// SetUnavailable simulates a backend outage. When nil, the outage
	// check is reported as skipped — never as passed.
	SetUnavailable func(down bool)
}

// Factory builds a fresh Harness. The provider must send all its logging to
// log, so that the suite can inspect it.
type Factory func(log *slog.Logger) Harness

// Result is the verdict of one check.
type Result struct {
	Check      string
	Violations []string
	Skipped    string // reason, when the check did not run
}

// Failed reports whether the check ran and found violations.
func (r Result) Failed() bool { return len(r.Violations) > 0 }

type check struct {
	name string
	run  func(e *env)
}

var checks = []check{
	{"write_resolve_roundtrip", checkRoundtrip},
	{"versions_distinct", checkVersions},
	{"read_idempotent", checkIdempotent},
	{"version_matches_resolve", checkVersionMeta},
	{"not_found_classified", checkNotFound},
	{"write_rejects_named_version", checkWriteNamedVersion},
	{"disable_two_phase", checkDisable},
	{"backend_unavailable", checkUnavailable},
	{"cancelled_context", checkCancelled},
	{"no_value_in_errors", checkErrorLeak},
}

// Checks returns the names of all checks, in order.
func Checks() []string {
	n := make([]string, len(checks))
	for i, c := range checks {
		n[i] = c.name
	}
	return n
}

// Check runs the suite and returns one Result per check. Leaks into logs,
// errors and Meta are checked inside every check, not only the dedicated one.
func Check(ctx context.Context, f Factory) []Result {
	out := make([]Result, 0, len(checks))
	for _, c := range checks {
		out = append(out, runOne(ctx, f, c))
	}
	return out
}

// Run runs the suite as subtests of t.
func Run(t *testing.T, f Factory) {
	t.Helper()
	for _, r := range Check(context.Background(), f) {
		t.Run(r.Check, func(t *testing.T) {
			if r.Skipped != "" {
				t.Skip(r.Skipped)
			}
			for _, v := range r.Violations {
				t.Error(v)
			}
		})
	}
}

func runOne(ctx context.Context, f Factory, c check) Result {
	return runOneWithCapture(ctx, f, c, captureStdio)
}

// The capture dependency is explicit so setup failures can be exercised
// without changing process limits or introducing mutable global hooks.
func runOneWithCapture(ctx context.Context, f Factory, c check, capture func(func()) (string, bool)) (res Result) {
	res.Check = c.name
	logs := &lockedBuffer{}
	e := &env{ctx: ctx, canary: newCanary(), path: "conformance/" + c.name}
	stdio, capturedOK := capture(func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(skip); ok {
					return
				}
				// A panic message may itself carry the value.
				msg := fmt.Sprint(r)
				if e.canary.in(msg) {
					msg = "<panic message contained the secret value>"
				}
				e.violate("provider panicked: %s", msg)
			}
		}()
		// The factory call itself runs inside the capture window, not
		// before it: a constructor that does its own one-shot debug print
		// would otherwise land on the real stdio before capture
		// ever started, and no capture technique can retroactively see it.
		h := f(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		e.h, e.p = h, h.Provider
		c.run(e)
	})
	if !capturedOK {
		// Fail closed: a capture we could not verify is not a clean result.
		e.violate("stdio leak capture could not be set up, drained or restored cleanly — treated as a leak until it can be verified")
	} else if e.canary.in(stdio) {
		e.violate("secret value found on process stdout/stderr")
	}
	if e.canary.in(logs.String()) {
		e.violate("secret value found in provider log output")
	}
	// A capability skip must never hide a detected violation from Run.
	if len(e.violations) > 0 {
		e.skipped = ""
	}
	res.Violations = e.violations
	res.Skipped = e.skipped
	return res
}

// stdioMu serializes captureStdio: file descriptors 1 and 2 are process-wide
// — two concurrent captures would redirect the same fd out from under each
// other and attribute one goroutine's output to another's capture (see
// TestCaptureStdio_SerializesConcurrentCaptures, which is the red run: it
// fails if this lock is removed).
var stdioMu sync.Mutex

// stdioDrainTimeout bounds how long captureStdio waits for its pipe to
// drain after fn returns and both fds are restored. A var, not a const, so
// tests can shrink it instead of waiting out the production value (see
// TestCaptureStdio_BoundedTimeoutOnStuckDrain). Without a bound, a writer
// that outlives fn (a goroutine fn spawned, or a child process fn started
// with Stdout/Stderr wired to the redirected fd) would hold the pipe's
// write end open forever, and captureStdio would hang until the surrounding
// `go test` timeout killed the whole binary with no named failure.
var stdioDrainTimeout = 5 * time.Second

// captureStdio redirects the process's real file descriptors 1 (stdout) and
// 2 (stderr) — not merely the os.Stdout/os.Stderr package variables — for
// the duration of fn, and returns everything written to either plus whether
// the capture and its drain completed cleanly.
//
// A provider is only required to send its logging to the *slog.Logger the
// factory hands it — nothing stops a stray debug print, a panic handler, or
// a vendored SDK's own logging from bypassing that logger. Redirecting the
// fd itself, rather than swapping the os.Stdout/os.Stderr variables, is
// what makes that visible regardless of how the write reaches the fd:
// the stdlib log package's default logger and slog's default handler both
// hold an *os.File captured once, at their own init time, not the live
// os.Stdout/os.Stderr variable; the println builtin and a direct
// syscall.Write(1|2, ...) never go through any Go-level *os.File at all.
// All of them ultimately reduce to a raw write on file descriptor number 1
// or 2, and dup2 makes that number itself point at our pipe — see
// leaky_stdout_test.go for the finding this replaced, which only proved the
// (still real, still checked) case a variable swap already caught.
//
// On failure to set up or restore the redirection, on a read error, or on a
// drain that does not finish within stdioDrainTimeout, ok is false: the caller
// must fail closed and treat this as an unverified result, never as "no leak found". Setup failure
// never invokes fn without capture.
//
// This window covers writes to fd 1/2 while fn runs. Async writes after the
// window closes, separate descriptors duplicated before the window, files
// opened before capture (including /dev/stdout), and other output channels
// are outside this guarantee. Providers must finish their output before
// returning and use the supplied logger. The window is process-wide: it
// absorbs unrelated diagnostics too, including test and race reports; those
// bytes are not forwarded because they may contain a value.
func captureStdio(fn func()) (out string, ok bool) {
	return captureStdioWithOps(fn, os.Pipe, redirectFD)
}

func captureStdioWithOps(fn func(), pipe func() (*os.File, *os.File, error), redirect func(int, *os.File) (func() error, error)) (out string, ok bool) {
	stdioMu.Lock()
	defer stdioMu.Unlock()

	r, w, err := pipe()
	if err != nil {
		return "", false
	}
	defer func() { _ = r.Close() }()

	restoreOut, err := redirect(1, w)
	if err != nil {
		_ = w.Close()
		return "", false
	}
	restoreErr, err := redirect(2, w)
	if err != nil {
		_ = restoreOut()
		_ = w.Close()
		return "", false
	}

	var buf lockedBuffer
	// Buffered so the reader can finish even after a panic or drain timeout.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(&buf, r)
		done <- err
	}()

	restored := true
	func() {
		defer func() {
			errErr := restoreErr()
			errOut := restoreOut()
			restored = errErr == nil && errOut == nil
			_ = w.Close()
		}()
		fn()
	}()

	select {
	case err := <-done:
		return buf.String(), err == nil && restored
	case <-time.After(stdioDrainTimeout):
		return buf.String(), false
	}
}

// redirectFD makes the OS-level file descriptor numbered fd point at to's
// underlying file, and returns a restore closure that points fd back at
// whatever it referenced before. Operating on the fd number below any Go
// variable is what lets captureStdio see writes through a reference a
// caller obtained before the redirect (including the stdlib's own default
// loggers, bound once at process init) — dup2 changes what the number
// itself resolves to, not any particular *os.File value.
func redirectFD(fd int, to *os.File) (restore func() error, err error) {
	saved, err := syscall.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("dup(%d): %w", fd, err)
	}
	if err := fdredirect.Dup2(int(to.Fd()), fd); err != nil {
		_ = syscall.Close(saved)
		return nil, fmt.Errorf("dup2(%d -> %d): %w", to.Fd(), fd, err)
	}
	return func() error {
		err := fdredirect.Dup2(saved, fd)
		_ = syscall.Close(saved)
		return err
	}, nil
}

type skip struct{}

type env struct {
	ctx        context.Context
	h          Harness
	p          provider.Provider
	canary     canary
	path       string
	violations []string
	skipped    string
}

func (e *env) violate(format string, a ...any) {
	e.violations = append(e.violations, fmt.Sprintf(format, a...))
}

func (e *env) skip(reason string) {
	e.skipped = reason
	panic(skip{})
}

func (e *env) ref(version string) provider.Ref { return provider.Ref{Path: e.path, Version: version} }

// observe checks an error and a Meta for leaks and classification.
func (e *env) observe(op string, m provider.Meta, err error) {
	if e.canary.in(fmt.Sprintf("%+v %#v", m, m)) {
		e.violate("%s: Meta contains the secret value", op)
	}
	if err == nil {
		return
	}
	if e.canary.in(err.Error()) || e.canary.in(fmt.Sprintf("%+v", err)) {
		e.violate("%s: error text contains the secret value", op)
	}
	if provider.Class(err) == nil {
		e.violate("%s: error is not classified (errors.Is matches no provider.Err*): %T", op, err)
	}
}

func (e *env) write(v secret.Value) (provider.Meta, error) {
	m, err := e.p.Write(e.ctx, e.ref(""), v)
	e.observe("Write", m, err)
	return m, err
}

func (e *env) resolve(version string) (secret.Value, provider.Meta, error) {
	v, m, err := e.p.Resolve(e.ctx, e.ref(version))
	e.observe("Resolve", m, err)
	return v, m, err
}

func (e *env) version(version string) (provider.Meta, error) {
	m, err := e.p.Version(e.ctx, e.ref(version))
	e.observe("Version", m, err)
	return m, err
}

func (e *env) disable(version string) error {
	err := e.p.Disable(e.ctx, e.ref(version))
	e.observe("Disable", provider.Meta{}, err)
	return err
}

func (e *env) needWrite() {
	if !e.p.Capabilities().Write {
		e.skip("provider does not declare Write; seed data support is required to run this check")
	}
}

func expectClass(e *env, op string, err, want error) {
	switch {
	case err == nil:
		e.violate("%s: expected %v, got nil", op, want)
	case !errors.Is(err, want):
		e.violate("%s: expected class %v, got class %v", op, want, provider.Class(err))
	}
}

// --- checks ---

func checkRoundtrip(e *env) {
	e.needWrite()
	v := e.canary.value(1)
	m, err := e.write(v)
	if err != nil {
		e.violate("Write failed: class %v", provider.Class(err))
		return
	}
	if m.Version == "" {
		e.violate("Write returned an empty version")
	}
	if m.Length != v.Len() {
		e.violate("Write Meta.Length = %d, want %d", m.Length, v.Len())
	}
	got, rm, err := e.resolve("")
	if err != nil {
		e.violate("Resolve after Write failed: class %v", provider.Class(err))
		return
	}
	if !got.Equal(v) {
		e.violate("Resolve returned a different value than was written")
	}
	if rm.Version != m.Version {
		e.violate("Resolve version %q != Write version %q", rm.Version, m.Version)
	}
}

func checkVersions(e *env) {
	e.needWrite()
	if !e.p.Capabilities().Versioning {
		e.skip("provider does not declare Versioning")
	}
	v1, v2 := e.canary.value(1), e.canary.value(2)
	m1, err1 := e.write(v1)
	m2, err2 := e.write(v2)
	if err1 != nil || err2 != nil {
		e.violate("Write failed")
		return
	}
	if m1.Version == m2.Version {
		e.violate("two writes produced the same version %q", m1.Version)
	}
	cur, cm, err := e.resolve("")
	if err != nil || !cur.Equal(v2) || cm.Version != m2.Version {
		e.violate("current version is not the latest write")
	}
	old, om, err := e.resolve(m1.Version)
	if err != nil {
		e.violate("previous version not resolvable after a new write (class %v): two-phase rotation impossible", provider.Class(err))
		return
	}
	if !old.Equal(v1) || om.Version != m1.Version {
		e.violate("resolving the previous version returned something else")
	}
}

func checkIdempotent(e *env) {
	e.needWrite()
	m, err := e.write(e.canary.value(1))
	if err != nil {
		e.violate("Write failed")
		return
	}
	for i := 0; i < 3; i++ {
		_, rm, err := e.resolve("")
		if err != nil || rm.Version != m.Version {
			e.violate("Resolve #%d changed the version or failed", i+1)
		}
		vm, err := e.version("")
		if err != nil || vm.Version != m.Version {
			e.violate("Version #%d changed the version or failed", i+1)
		}
	}
}

func checkVersionMeta(e *env) {
	e.needWrite()
	v := e.canary.value(1)
	if _, err := e.write(v); err != nil {
		e.violate("Write failed")
		return
	}
	vm, err := e.version("")
	if err != nil {
		e.violate("Version failed: class %v", provider.Class(err))
		return
	}
	_, rm, _ := e.resolve("")
	if vm.Version != rm.Version || vm.Length != rm.Length || vm.Length != v.Len() {
		e.violate("Version meta %+v disagrees with Resolve meta %+v", vm, rm)
	}
}

func checkNotFound(e *env) {
	_, _, err := e.resolve("")
	expectClass(e, "Resolve(missing)", err, provider.ErrNotFound)
	_, err = e.version("")
	expectClass(e, "Version(missing)", err, provider.ErrNotFound)
	_, _, err = e.p.Resolve(e.ctx, provider.Ref{})
	e.observe("Resolve(empty ref)", provider.Meta{}, err)
	expectClass(e, "Resolve(empty ref)", err, provider.ErrInvalidRef)
}

func checkWriteNamedVersion(e *env) {
	e.needWrite()
	m, err := e.p.Write(e.ctx, e.ref("1"), e.canary.value(1))
	e.observe("Write(named version)", m, err)
	expectClass(e, "Write(named version)", err, provider.ErrInvalidRef)
}

func checkDisable(e *env) {
	e.needWrite()
	c := e.p.Capabilities()
	if !c.Disable || !c.Versioning {
		e.skip("provider does not declare Disable+Versioning")
	}
	m1, _ := e.write(e.canary.value(1))
	m2, err := e.write(e.canary.value(2))
	if err != nil {
		e.violate("Write failed")
		return
	}
	if err := e.disable(m1.Version); err != nil {
		e.violate("Disable(previous) failed: class %v", provider.Class(err))
		return
	}
	_, _, err = e.resolve(m1.Version)
	expectClass(e, "Resolve(disabled)", err, provider.ErrDisabled)
	if _, cm, err := e.resolve(""); err != nil || cm.Version != m2.Version {
		e.violate("current version changed after disabling the previous one")
	}
	if err := e.disable(m1.Version); err != nil {
		e.violate("Disable is not idempotent: second call failed with class %v", provider.Class(err))
	}
	expectClass(e, "Disable(last enabled)", e.disable(m2.Version), provider.ErrLastVersion)
	if _, _, err := e.resolve(""); err != nil {
		e.violate("secret became unresolvable after a refused Disable of the last version")
	}
	expectClass(e, "Disable(no version)", e.disable(""), provider.ErrInvalidRef)
}

func checkUnavailable(e *env) {
	if e.h.SetUnavailable == nil {
		e.skip("harness has no SetUnavailable control")
	}
	var seeded provider.Meta
	if e.p.Capabilities().Write {
		var err error
		if seeded, err = e.write(e.canary.value(1)); err != nil {
			e.violate("Write failed")
			return
		}
	}
	e.h.SetUnavailable(true)
	v, _, err := e.resolve("")
	expectClass(e, "Resolve(outage)", err, provider.ErrUnavailable)
	if !v.IsZero() {
		e.violate("Resolve returned a value together with an outage")
	}
	_, err = e.version("")
	expectClass(e, "Version(outage)", err, provider.ErrUnavailable)
	if e.p.Capabilities().Write {
		_, err = e.write(e.canary.value(2))
		expectClass(e, "Write(outage)", err, provider.ErrUnavailable)
	}
	e.h.SetUnavailable(false)
	if e.p.Capabilities().Write {
		if _, m, err := e.resolve(""); err != nil || m.Version != seeded.Version {
			e.violate("data or version changed across an outage (a Write during the outage must not have landed)")
		}
	}
}

func checkCancelled(e *env) {
	e.needWrite()
	if _, err := e.write(e.canary.value(1)); err != nil {
		e.violate("Write failed")
		return
	}
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	v, m, err := e.p.Resolve(ctx, e.ref(""))
	e.observe("Resolve(cancelled)", m, err)
	if err == nil || !v.IsZero() {
		e.violate("Resolve with a cancelled context returned a value")
	}
}

// checkErrorLeak provokes every error path while the canary is stored and
// passed in, so a provider that echoes values into errors has a chance to.
func checkErrorLeak(e *env) {
	e.needWrite()
	v := e.canary.value(1)
	m, err := e.write(v)
	if err != nil {
		e.violate("Write failed")
		return
	}
	_, _, _ = e.resolve("999999")
	_, _, _ = e.resolve("not-a-version")
	_, _ = e.version("999999")
	_, err = e.p.Write(e.ctx, e.ref(m.Version), v)
	e.observe("Write(named version, canary)", provider.Meta{}, err)
	if e.p.Capabilities().Disable {
		_ = e.disable(m.Version) // last enabled version: must fail, without the value
	}
	if e.h.SetUnavailable != nil {
		e.h.SetUnavailable(true)
		_, _, _ = e.resolve("")
		_, _ = e.write(v)
		e.h.SetUnavailable(false)
	}
}

// --- canary ---

type canary struct{ base string }

func newCanary() canary {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return canary{base: "kc" + hex.EncodeToString(b)}
}

// value returns the i-th canary value; every value contains the base.
func (c canary) value(i int) secret.Value {
	return secret.New([]byte(fmt.Sprintf("%s-v%d-secret", c.base, i)))
}

// in reports whether s contains the canary base in any common encoding.
func (c canary) in(s string) bool {
	if s == "" {
		return false
	}
	for _, enc := range c.encodings() {
		if strings.Contains(s, enc) || strings.Contains(strings.ToLower(s), strings.ToLower(enc)) {
			return true
		}
	}
	return false
}

func (c canary) encodings() []string {
	raw := []byte(c.base)
	out := []string{
		c.base,
		hex.EncodeToString(raw),
		url.QueryEscape(c.base),
		reverse(c.base),
	}
	out = append(out, canaryBase64Alignments(raw, base64.StdEncoding)...)
	out = append(out, canaryBase64Alignments(raw, base64.RawURLEncoding)...)
	return out
}

// canaryBase64Alignments returns the substrings of raw's base64 encoding
// that are safe to search for regardless of where raw's first byte falls
// within a larger encoded buffer.
//
// Base64 groups bytes three at a time. A real leak rarely encodes raw in
// isolation, so raw's first byte can land at any of three positions (its
// index mod 3) within its 3-byte group, and each position produces a
// different run of characters for the bytes straddling raw's boundary,
// because those characters also encode bits from the unknown neighboring
// byte(s). Checking only the offset-0 alignment (the original bug here:
// encoding raw on its own always starts a fresh group) is blind to the
// other two — see internal/testutil/canary for the same fix and its test,
// which is the canonical writeup; this package carries its own standalone
// copy of the helper (see the package comment there) and needed the
// identical fix applied separately.
//
// For each of the three possible offsets, this re-encodes raw prefixed
// with `offset` placeholder bytes, then keeps only the run of characters
// that comes from whole groups made entirely of raw's own bytes — never a
// group straddling the placeholder/raw or raw/(whatever follows) boundary,
// since that group's characters depend on bytes we don't and can't know.
// The placeholder's actual value is therefore irrelevant; it's discarded,
// never compared.
func canaryBase64Alignments(raw []byte, enc *base64.Encoding) []string {
	var out []string
	for offset := 0; offset <= 2; offset++ {
		padded := make([]byte, offset, offset+len(raw))
		padded = append(padded, raw...)
		encoded := enc.EncodeToString(padded)

		firstPureGroup := (offset + 2) / 3   // ceil(offset/3)
		groupsEnd := (offset + len(raw)) / 3 // floor((offset+len(raw))/3)
		if groupsEnd <= firstPureGroup {
			continue // raw too short at this offset to yield a whole clean group
		}
		out = append(out, encoded[4*firstPureGroup:4*groupsEnd])
	}
	return out
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
