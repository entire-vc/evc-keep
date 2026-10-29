//go:build unix

package targets

import (
	"bytes"
	"errors"
	"io"
	"os/exec"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"golang.org/x/sys/unix"
)

// systemdCredentialHandler encrypts the value with `systemd-creds encrypt`
// when a trusted binary exists at the fixed path below — the value never
// touches argv or the environment, only a pipe to the child's stdin — and
// writes the resulting ciphertext. Where there is no such binary (every CI
// image this repo builds on, and any non-systemd host), it falls back to
// writing the value as-is at the target's mode, same as the "file" kind:
// still 0600 and still under this package's write path, just not sealed to
// the host — but only when the host's policy allows it
// (SystemdCredPlaintextFallback); otherwise the target is refused, because a
// silent drop to less protection is exactly what the policy flag exists to
// prevent.
//
// The binary is NOT looked up on PATH. Whoever controls one PATH directory
// (on a host where an agent account owns a PATH directory) would receive the
// value on stdin from a planted binary of that name. The path is fixed, the
// file must be a plain file (not a symlink) owned by root and writable by
// neither group nor others, and the child gets a minimal environment.
// "There is no binary" means "nothing at the fixed path" and nothing else: a
// binary that is present but not trustworthy is a refusal, never a quiet
// fall-back to plaintext.
type systemdCredentialHandler struct {
	// plaintextFallback is HostPolicy.SystemdCredPlaintextFallback: without
	// it a host with no systemd-creds refuses the target.
	plaintextFallback bool
	// usedFallback, if not nil, is set when build chose the plaintext
	// fallback, so Write can force the file mode and report the use only
	// once the file is actually written.
	usedFallback *bool
}

// sealToolPath and sealToolTrustedUID are variables only so a test
// can point them at a stand-in; production never assigns them.
var (
	sealToolPath = "/usr/bin/systemd-creds"

	// sealToolTrustedUID is the only owner the binary may have: root.
	sealToolTrustedUID int64
)

// findSystemdCreds resolves the fixed path. present=false, nil error: no
// file there (use the fallback). A non-nil error: something is there and it
// cannot be trusted, or it cannot be examined.
func findSystemdCreds() (path string, present bool, err error) {
	var st unix.Stat_t
	if err := unix.Lstat(sealToolPath, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", false, nil
		}
		return "", false, writeFailed("stat systemd-creds: %v", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return "", true, denied("systemd-creds at %s is not a plain file", sealToolPath)
	case int64(st.Uid) != sealToolTrustedUID:
		return "", true, denied("systemd-creds at %s is not owned by the trusted owner", sealToolPath)
	case st.Mode&0o022 != 0:
		return "", true, denied("systemd-creds at %s is writable by group or others", sealToolPath)
	}
	return sealToolPath, true, nil
}

func credName(t runnerproto.Target) string {
	if t.Field != "" {
		return t.Field
	}
	return t.Unit
}

func (systemdCredentialHandler) foldsExisting() bool { return false }

func (h systemdCredentialHandler) build(_ []byte, _ bool, t runnerproto.Target, v secret.Value) ([]byte, error) {
	path, present, err := findSystemdCreds()
	if err != nil {
		return nil, err
	}
	if !present {
		if !h.plaintextFallback {
			return nil, denied("systemd-creds is not available and the host policy does not allow the plaintext fallback")
		}
		if h.usedFallback != nil {
			*h.usedFallback = true
		}
		return bytesOf(v), nil
	}
	val := bytesOf(v)
	defer wipe(val)
	args := []string{"encrypt"}
	if name := credName(t); name != "" {
		args = append(args, "--name="+name)
	}
	args = append(args, "-", "-")
	out, err := runPiped(path, args, val)
	if err != nil {
		return nil, writeFailed("systemd-creds encrypt: %v", err)
	}
	return out, nil
}

func (h systemdCredentialHandler) readBack(content []byte, t runnerproto.Target) (secret.Value, error) {
	path, present, err := findSystemdCreds()
	if err != nil {
		return secret.Value{}, err
	}
	if !present {
		return secret.New(content), nil
	}
	args := []string{"decrypt"}
	if name := credName(t); name != "" {
		args = append(args, "--name="+name)
	}
	args = append(args, "-", "-")
	out, err := runPiped(path, args, content)
	if err != nil {
		return secret.Value{}, writeFailed("systemd-creds decrypt (round-trip check): %v", err)
	}
	defer wipe(out)
	return secret.New(out), nil
}

// childEnv is everything the child sees: no inherited variable, in
// particular nothing from the runner's own environment.
var childEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

// pipeChunk is how many bytes runPiped reads from the child at a time. Not a
// power of two on purpose: the output starts at 512 and doubles, and
// TestRunPipedWipesPartialStdoutOnFailure tells the chunk from a growth step
// by its length.
const pipeChunk = 4000

// runPiped runs path with stdin on a pipe and returns the child's stdout. The
// stdout of decrypt is the plaintext, so every copy this function makes is
// one it wipes (a new copy of out must go through wipe too): exec's own copier (a hidden 32 KiB buffer, unreachable from
// here) is bypassed by reading the pipe directly into a chunk we own, and the
// output grows by allocate-copy-wipe instead of bytes.Buffer's abandon. On
// any failure the partial output is wiped and nothing is returned; on success
// the caller owns the returned slice and wipes it.
func runPiped(path string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(path, args...) //nolint:gosec // G204: path is the fixed, ownership-checked sealToolPath, args are fixed flags plus our own target name
	cmd.Env = childEnv
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(stdin)
	// Stderr is intentionally not captured: systemd-creds' own diagnostics
	// could echo back something derived from its input on a malformed run,
	// and nothing in this package may let value-derived text reach a log.
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	chunk := make([]byte, pipeChunk)
	defer wipe(chunk)
	out := make([]byte, 0, 512)
	done := false
	defer func() {
		if !done {
			wipe(out[:cap(out)]) // failed run
		}
	}()
	var readErr error
	for {
		n, err := pipe.Read(chunk)
		if n > 0 {
			if len(out)+n > cap(out) {
				grown := make([]byte, len(out), max(2*cap(out), len(out)+n))
				copy(grown, out)
				wipe(out[:cap(out)]) // abandoned step
				out = grown
			}
			out = append(out, chunk[:n]...)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	if readErr != nil {
		// A child still writing into a full pipe would never let Wait return.
		_ = pipe.Close()
	}
	waitErr := cmd.Wait()
	if readErr == nil {
		readErr = waitErr
	}
	if readErr != nil {
		return nil, readErr
	}
	done = true
	return out, nil
}
