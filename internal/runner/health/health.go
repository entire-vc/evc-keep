// Package health restarts a job's consumer and checks its health
// afterwards. Both the restart command and the healthcheck's own
// parameters come from the host's local
// runnerproto.HostPolicy, never from the signed job — see HealthCheck's doc
// comment in pkg/runnerproto/policy.go for why: a compromised server must
// not be able to supply its own trivially-passing check.
package health

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// maxHTTPBodyBytes bounds how much of an http check's response this
// package will ever read, so a runaway or malicious consumer cannot make a
// healthcheck consume unbounded memory. Well past any real marker.
const maxHTTPBodyBytes = 1 << 20

// errHealth wraps every refusal from this package: a malformed consumer, an
// unknown domain, a restart or check that failed to even run. Arguments to
// its formatting helper are a consumer string, a domain, or a fixed literal
// — never a Go error's own text, a healthcheck response body, or a
// consumer's own log output, which this package never reads in the first
// place.
var errHealth = errors.New("health: failed")

func failed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errHealth, fmt.Sprintf(format, a...))
}

// runner executes a restart or status command for a consumer. Real use is
// execRunner via defaultRunner; tests swap defaultRunner for a fake so the
// red-run cases in health_test.go run deterministically, without a real
// launchd/systemd on the test host — the same package-level-var injection
// pattern internal/targets uses for afterTmpCreate/afterChmod.
type runner interface {
	// Run executes argv to completion and returns its stdout — used only to
	// parse a unit's *state* (exit code, and for launchd a small fixed
	// vocabulary of state words in `launchctl list`'s output), never logged
	// or returned by this package.
	Run(ctx context.Context, argv []string) ([]byte, error)
}

// execRunner runs argv as a real subprocess via os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, argv []string) ([]byte, error) {
	//nolint:gosec // G204: argv[0] is one of two fixed binary paths this package hardcodes (launchctl, systemctl); the rest is a validated consumer name, never free-form input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// launchctl/systemctl never need this process's own environment; an
	// explicit empty Env keeps any secret-bearing variable here from ever
	// reaching a child process this package doesn't otherwise control.
	cmd.Env = []string{}
	// Output returns stdout only — a failure's stderr lands in the
	// returned *exec.ExitError.Stderr instead, and this package reads
	// neither past the fixed state words it looks for below.
	return cmd.Output()
}

// defaultRunner is the runner Run uses in production; health_test.go swaps
// it for a fake around each Run call that needs one.
var defaultRunner runner = execRunner{}

// splitConsumer splits a Target.Consumer ("launchd:<label>" or
// "systemd:<unit>") already validated by runnerproto.Target.Validate — see
// its consumerRe. This package re-checks the domain regardless: it must not
// trust an unvalidated caller to have run that check.
func splitConsumer(consumer string) (domain, name string, err error) {
	domain, name, ok := strings.Cut(consumer, ":")
	if !ok || name == "" {
		return "", "", failed("malformed consumer %q", consumer)
	}
	switch domain {
	case "launchd", "systemd":
		return domain, name, nil
	default:
		return "", "", failed("unknown consumer domain %q", domain)
	}
}

// restartArgv returns the argv that restarts consumer, addressed at uid —
// the target's own owner (runnerproto.Target.UID), the consumer's identity,
// never the agent's or the runner's own.
func restartArgv(consumer string, uid int64) ([]string, error) {
	domain, name, err := splitConsumer(consumer)
	if err != nil {
		return nil, err
	}
	switch domain {
	case "launchd":
		return []string{"/bin/launchctl", "kickstart", "-k", fmt.Sprintf("user/%d/%s", uid, name)}, nil
	default: // systemd
		return []string{"/usr/bin/systemctl", "restart", name}, nil
	}
}

// restart restarts consumer via r and nothing else: exactly launchctl
// kickstart -k (launchd) or systemctl restart (systemd), no other command.
func restart(ctx context.Context, r runner, consumer string, uid int64) error {
	argv, err := restartArgv(consumer, uid)
	if err != nil {
		return err
	}
	if _, err := r.Run(ctx, argv); err != nil {
		// Never err's own text: a subprocess failure's message can echo
		// back argv or output content this package doesn't control.
		return failed("restart %q: command failed", consumer)
	}
	return nil
}

// isActive reports whether consumer is currently running. For systemd,
// `systemctl is-active` alone carries the answer in its exit status.
//
// For launchd this deliberately does NOT use `launchctl print`: print dumps
// a job's entire EnvironmentVariables block verbatim into its output — a
// live leak surface for any launchd-env secret target, confirmed against
// real jobs on this host. `launchctl list <name>` instead: its plist
// carries only Label/PID/ProgramArguments/MachServices/LastExitStatus, none
// of it consumer-controlled content, and a PID key is present only while
// the job is actually running.
//
// Trade-off, open question: unlike print/kickstart/bootout, `list` has no
// domain-target syntax (`man launchctl`: list operates only on the
// caller's own bootstrap/session domain) — so this only works when the
// runner process executes as the SAME uid as the consumer. A runner
// managing another uid's launchd jobs (as restart's `user/<uid>/<name>`
// domain target can) cannot use list to check them; there is no
// privilege-drop precedent elsewhere in this repo to reach for instead.
func isActive(ctx context.Context, r runner, consumer string, uid int64) (bool, error) {
	domain, name, err := splitConsumer(consumer)
	if err != nil {
		return false, err
	}
	switch domain {
	case "launchd":
		out, err := r.Run(ctx, []string{"/bin/launchctl", "list", name})
		if err != nil {
			return false, nil // not listed (unloaded, crashed out, wrong uid) => not active
		}
		return launchdIsRunning(out), nil
	default: // systemd
		// `systemctl is-active` carries the whole answer in its exit
		// status: 0 only for "active", non-zero for inactive/failed/
		// activating. Unlike launchd's `list` (loaded but not running
		// still exits 0), there is no state the exit code hides here, so
		// this trusts it directly rather than also re-parsing the word it
		// prints.
		_, err := r.Run(ctx, []string{"/usr/bin/systemctl", "is-active", name})
		return err == nil, nil
	}
}

// launchdIsRunning reports whether `launchctl list <name>`'s plist output
// names a PID — present only while the job is actually running, absent
// when loaded-but-stopped or crashed. A single fixed key to look for, never
// anything the job itself could shape: list's output carries no
// consumer-controlled content at all.
func launchdIsRunning(out []byte) bool {
	return bytes.Contains(out, []byte(`"PID" = `))
}

// runUnitActive waits settle after a restart already performed by the
// caller, then reports whether consumer is still active. It never reads the
// consumer's own stdout, stderr or log file — a crashed consumer's own
// output is not this check's business, and might itself carry sensitive
// detail that isn't this package's to forward.
func runUnitActive(ctx context.Context, r runner, consumer string, uid int64, settle time.Duration) (bool, error) {
	select {
	case <-time.After(settle):
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return isActive(ctx, r, consumer, uid)
}

// httpClientFor returns a client bounded by h's own timeout, so a hung
// loopback listener cannot stall a deploy forever, and that never follows a
// redirect: a redirect response otherwise lets the checked consumer point
// this check at a URL host policy never validated as loopback-only.
func httpClientFor(h runnerproto.HealthCheck) *http.Client {
	return &http.Client{
		Timeout: time.Duration(h.TimeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// runHTTP performs the http healthcheck: a GET to h.URL — already validated
// loopback-only by runnerproto.HostPolicy.Validate, never re-parsed or
// re-trusted here as anything but what it is — requiring h.ExpectStatus and
// h.BodyMarker in the body within h.TimeoutSeconds.
//
// The body is read only to test for the marker's presence and never kept,
// logged, wrapped into an error, or returned: not by this function, and not
// by any error path below it. That holds even when the body itself carries
// something that looks like a canary or a secret — see
// TestRunHTTPNeverLeaksBody.
func runHTTP(ctx context.Context, client *http.Client, h runnerproto.HealthCheck) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		// Never err's own text: url.Parse's error can echo the URL back.
		return false, failed("build request: malformed url")
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil // network error or timeout: unhealthy, not a hard failure
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != int(h.ExpectStatus) {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPBodyBytes))
		return false, nil
	}
	return markerInBody(resp.Body, h.BodyMarker), nil
}

// markerInBody reads r (bounded to maxHTTPBodyBytes) and reports whether it
// contains marker. Isolated from runHTTP so the body is never kept, logged
// or returned by anything above this function: it hands back a bool, never
// the bytes it read.
func markerInBody(r io.Reader, marker string) bool {
	body, err := io.ReadAll(io.LimitReader(r, maxHTTPBodyBytes))
	if err != nil {
		return false // truncated/aborted read: unhealthy, not a hard failure
	}
	return hasMarker(body, marker)
}

// hasMarker is markerInBody's own comparison, split out so a mutation
// removing this call cannot strand markerInBody's already-read body as an
// unused local — an unused function PARAMETER here, unlike an unused local
// variable, is not a compile error.
func hasMarker(body []byte, marker string) bool {
	return bytes.Contains(body, []byte(marker))
}

// Outcome is one healthcheck's result, ready to attach to
// runnerproto.Result.Healthcheck.
type Outcome struct {
	Status     runnerproto.HealthStatus
	Kind       runnerproto.HealthKind
	DurationMs int64
}

// Run restarts t.Consumer and, if h names a kind, checks its health
// afterward; h is the zero value when host policy defines no check for
// this target (runnerproto.ResolveHealth), in which case Run restarts but
// reports HealthSkipped. t.Consumer == "" means no restart and no check at
// all — Run must not be called in that case; callers check t.Consumer
// first.
//
// When h.Kind == "" (no check configured) AND the restart itself fails, this
// returns Outcome{Status: HealthFailed, Kind: ""}, a combination
// runnerproto.Result.Validate rejects (an empty kind is valid only with
// HealthSkipped). deploy.Apply maps it to error class healthcheck_failed with
// no Healthcheck object.
func Run(ctx context.Context, t runnerproto.Target, h runnerproto.HealthCheck) Outcome {
	start := time.Now()
	if err := restart(ctx, defaultRunner, t.Consumer, t.UID); err != nil {
		return Outcome{Status: runnerproto.HealthFailed, Kind: h.Kind, DurationMs: time.Since(start).Milliseconds()}
	}
	if h.Kind == "" {
		return Outcome{Status: runnerproto.HealthSkipped, DurationMs: time.Since(start).Milliseconds()}
	}
	var ok bool
	switch h.Kind {
	case runnerproto.HealthKindUnitActive:
		ok, _ = runUnitActive(ctx, defaultRunner, t.Consumer, t.UID, time.Duration(h.SettleSeconds)*time.Second)
	case runnerproto.HealthKindHTTP:
		ok, _ = runHTTP(ctx, httpClientFor(h), h)
	}
	status := runnerproto.HealthFailed
	if ok {
		status = runnerproto.HealthOK
	}
	return Outcome{Status: status, Kind: h.Kind, DurationMs: time.Since(start).Milliseconds()}
}

// EmitEvent logs a "deploy.healthcheck" journal event for out. Its fields
// are exactly out's own closed-enum status/kind and a duration — never the
// consumer's own output, the http check's URL, its body marker, or its
// response body, none of which this package keeps past the pass/fail
// comparison that produced out in the first place. log must be a
// *slog.Logger built over internal/obs.Handler, whose closed attribute-key
// allow-list is the actual enforcement point, not this function's care in
// choosing keys.
func EmitEvent(log *slog.Logger, out Outcome) {
	log.Info("deploy.healthcheck",
		"status", string(out.Status),
		"kind", string(out.Kind),
		"duration_ms", out.DurationMs,
	)
}
