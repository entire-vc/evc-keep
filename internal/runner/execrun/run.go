package execrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Pin is one destination of an allowlist template after resolution: the
// address the child may reach, and the name the template gave it ("" for an
// address literal), which the child's fixed hosts file maps to that address.
type Pin struct {
	Host string
	Addr netip.AddrPort
}

// Isolator cuts a child process off the network. An implementation lives in
// the OS-specific files; Run only asks it two questions.
type Isolator interface {
	// Enforces reports whether this host can enforce mode right now.
	Enforces(mode execpolicy.NetMode) bool
	// Prepare makes a network that is empty (NetNone) or leads only to pins
	// (NetAllowlist), and returns the command prefix that runs a program in
	// it, and what to call when the program has exited. The isolator never
	// sees the child's environment: Run starts the process itself.
	Prepare(mode execpolicy.NetMode, pins []Pin) (wrap []string, cleanup func(), err error)
}

// Deps are the host's fixed choices; none of them comes from a job.
type Deps struct {
	Iso Isolator
	// HomeRoot is the directory a new, private HOME (also the child's TMPDIR
	// and working directory) is made in for every run and removed from after
	// it. Required: a child with the runner's own directories would see its
	// files, and a directory shared between runs would hand one run's files
	// to the next.
	HomeRoot string
	// ChildUID and ChildGID are the account the child runs as, apart from
	// the runner's own. Required: the child is never left with the runner's
	// account, which can read the runner's keys.
	ChildUID, ChildGID uint32
	// Path is the child's PATH; default /usr/bin:/bin.
	Path string
	// MaxOutput caps each of stdout and stderr, in bytes; default 64 KiB.
	MaxOutput int
	// Timeout bounds the run; default 60 s.
	Timeout time.Duration
	// Resolve names to addresses before the start; default the system
	// resolver. The child never resolves: it has no DNS.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Log must be built over internal/obs.
	Log *slog.Logger
	// CorePiped replaces the host's core_pattern check; nil (always, in the
	// runner) reads the host. A seam for tests of the packages above this one,
	// which run on CI hosts whose core_pattern is piped to a handler.
	CorePiped func() bool
	// Chown gives a run's directory to the child's account; nil (always, in
	// the runner) is os.Chown. Only tests set it, as they run without the
	// right to give a directory away.
	Chown func(path string, uid, gid int) error
}

// Outcome is what stays on the host after a run: the exit code and the
// scrubbed, limited output.
type Outcome struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	Truncated bool
}

// dropAccount gives an unwrapped child its own account; a variable only so
// the tests of Run's other rules can run without being root.
var dropAccount = dropToChild

// coreHandlerPiped is a variable only so tests on a host with a piped
// core_pattern can run.
var coreHandlerPiped = corePipedToAHandler

// geteuid and removeChildDir are variables only so tests can exercise the
// non-root and cannot-remove paths from a root CI container.
var (
	geteuid        = os.Geteuid
	removeChildDir = os.RemoveAll
)

// runMu serialises runs on the host.
var runMu sync.Mutex

const (
	defaultPath      = "/usr/bin:/bin"
	defaultMaxOutput = 64 << 10
	defaultTimeout   = 60 * time.Second
)

// Run executes a prepared plan. The class is empty on a run that reached the
// child, whatever the child's exit code; policy_denied when the host cannot
// enforce the template's network; internal_error otherwise. No text of a
// refusal leaves this function except through the host's own log.
func Run(ctx context.Context, pl Plan, v secret.Value, p runnerproto.HostPolicy, d Deps) (Outcome, runnerproto.ErrorClass) {
	start := time.Now()
	out, class, err := run(ctx, pl, v, p, d)
	d.logRun(pl, out, class, start, err)
	return out, class
}

func run(ctx context.Context, pl Plan, v secret.Value, p runnerproto.HostPolicy, d Deps) (rout Outcome, rclass runnerproto.ErrorClass, rerr error) {
	if d.HomeRoot == "" {
		return Outcome{}, runnerproto.ErrClassInternal, errors.New("home root is required")
	}
	if d.ChildUID == 0 || d.ChildGID == 0 {
		return Outcome{}, runnerproto.ErrClassInternal, errors.New("the child account is required")
	}
	// One run at a time: the child's home, its account and what is swept
	// after it are shared.
	runMu.Lock()
	defer runMu.Unlock()
	// The account must be the child's alone: not the runner's, not an agent's,
	// and with no process alive that could read the child's environment.
	if int64(d.ChildUID) == int64(geteuid()) || containsInt64(p.AgentUIDs, int64(d.ChildUID)) {
		return Outcome{}, runnerproto.ErrClassInternal, errors.New("the child account is the runner's or an agent's")
	}
	if err := accountClear(d.ChildUID); err != nil {
		return Outcome{}, runnerproto.ErrClassInternal, err
	}
	piped := coreHandlerPiped
	if d.CorePiped != nil {
		piped = d.CorePiped
	}
	if piped() {
		return Outcome{}, runnerproto.ErrClassInternal, errors.New("core dumps go to a handler program that records the environment; set core_pattern to a plain file name")
	}
	enforced := d.Iso != nil && d.Iso.Enforces(pl.Mode)
	switch {
	case enforced:
	case pl.Mode == execpolicy.NetAllowlist:
		// A pinned network cannot be promised without the OS enforcing it,
		// whatever the administrator accepted for network none.
		return Outcome{}, runnerproto.ErrClassPolicyDenied, errors.New("host cannot pin the network of an allowlist template")
	case !p.ExecNetUnenforced:
		return Outcome{}, runnerproto.ErrClassPolicyDenied, errors.New("host cannot cut a template off the network and exec_net_unenforced is not set")
	}

	// The limit bounds the whole run, destination resolution included.
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var addrs []Pin
	if pl.Mode == execpolicy.NetAllowlist {
		var err error
		if addrs, err = resolveAll(ctx, pl.Dests, d); err != nil {
			return Outcome{}, runnerproto.ErrClassPolicyDenied, err
		}
	}

	max := d.MaxOutput
	if max <= 0 {
		max = defaultMaxOutput
	}
	sc := newScrubber(v)
	defer sc.Wipe()
	keep := max + sc.maxNeedle()
	var stdout, stderr capWriter
	stdout.limit, stderr.limit = keep, keep

	var wrap []string
	var cleanup func()
	if enforced {
		var err error
		if wrap, cleanup, err = d.Iso.Prepare(pl.Mode, addrs); err != nil {
			return Outcome{}, runnerproto.ErrClassInternal, fmt.Errorf("isolate: %w", err)
		}
		defer cleanup()
		// The isolator is what changes the account in this path.
		if len(wrap) == 0 {
			return Outcome{}, runnerproto.ErrClassInternal, errors.New("the isolator returned no wrapper")
		}
	}
	if !homeRootEmpty(d.HomeRoot) {
		return Outcome{}, runnerproto.ErrClassInternal, errHomeRootNotEmpty
	}
	home, err := newRunDir(d.HomeRoot, d.ChildUID, d.ChildGID, d.Chown)
	if err != nil {
		return Outcome{}, runnerproto.ErrClassInternal, fmt.Errorf("make child home: %w", err)
	}
	// Removed again below once the child's processes are gone; this one
	// covers the paths that leave before the child starts. A directory that
	// stays is never hidden behind the refusal that got us here: the class
	// becomes internal_error and the first cause is kept for the log line.
	homeGone := false
	defer func() {
		if homeGone {
			return
		}
		cerr := removeChildDir(home)
		if cerr == nil {
			return
		}
		if rclass != runnerproto.ErrClassInternal {
			rerr = errors.Join(errCleanupAfterRefusal, fmt.Errorf("first refusal: %s", rclass), rerr, cerr)
			rclass = runnerproto.ErrClassInternal
			return
		}
		rerr = errors.Join(rerr, cerr)
	}()
	argv := append(append(append([]string(nil), wrap...), pl.Bin), pl.Args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: argv[0] is the isolator's tool or pl.Bin, the policy-checked real path
	cmd.Dir = home
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	path := d.Path
	if path == "" {
		path = defaultPath
	}
	cmd.Env = []string{"PATH=" + path, "HOME=" + home, "TMPDIR=" + home}
	secret.Expose(v, func(raw []byte) {
		for _, name := range pl.SecretEnv {
			cmd.Env = append(cmd.Env, name+"="+string(raw))
		}
	})
	setupProc(cmd)
	if !enforced {
		// Nothing wraps the child, so it is the runner that gives up its own
		// account; without that the child could read the runner's keys.
		if err := dropAccount(cmd, d.ChildUID, d.ChildGID); err != nil {
			return Outcome{}, runnerproto.ErrClassPolicyDenied, err
		}
	}
	if err := cmd.Start(); err != nil {
		return Outcome{}, runnerproto.ErrClassInternal, fmt.Errorf("start: %w", err)
	}
	werr := cmd.Wait()
	// Whatever the child left running holds the value in its environment:
	// the group first, then, for what left the group, every process of the
	// child's account.
	killGroup(cmd)
	cmd.Env = nil
	homeErr := errors.Join(sweepAccount(d.ChildUID), removeChildDir(home))
	homeGone = true // reported below, not by the early-exit defer

	res := Outcome{ExitCode: cmd.ProcessState.ExitCode()}
	var truncOut, truncErr bool
	res.Stdout, truncOut = sc.Scrub(stdout.buf.Bytes(), stdout.total > keep, max)
	res.Stderr, truncErr = sc.Scrub(stderr.buf.Bytes(), stderr.total > keep, max)
	clear(stdout.buf.Bytes())
	clear(stderr.buf.Bytes())
	res.Truncated = truncOut || truncErr
	if ctx.Err() != nil {
		return res, runnerproto.ErrClassInternal, fmt.Errorf("run: %w", ctx.Err())
	}
	if homeErr != nil {
		return res, runnerproto.ErrClassInternal, fmt.Errorf("clean child home: %w", homeErr)
	}
	var ee *exec.ExitError
	if werr != nil && !errors.As(werr, &ee) {
		return res, runnerproto.ErrClassInternal, fmt.Errorf("wait: %w", werr)
	}
	return res, "", nil
}

// resolveAll turns the template's destinations into addresses before the
// child exists. Every address must be one an approver could have meant: not
// the host itself, not a link-local address (cloud metadata lives there),
// not unspecified or multicast.
func resolveAll(ctx context.Context, dests []execpolicy.Destination, d Deps) ([]Pin, error) {
	resolve := d.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	var out []Pin
	for _, dst := range dests {
		var ips []netip.Addr
		name := dst.Host
		if ip, err := netip.ParseAddr(dst.Host); err == nil {
			ips, name = []netip.Addr{ip}, ""
		} else {
			var rerr error
			if ips, rerr = resolve(ctx, dst.Host); rerr != nil {
				return nil, fmt.Errorf("destination does not resolve: %w", rerr)
			}
		}
		if len(ips) == 0 {
			return nil, errors.New("destination resolves to nothing")
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
				return nil, errors.New("destination resolves to an address that is not allowed")
			}
			out = append(out, Pin{Host: name, Addr: netip.AddrPortFrom(ip, uint16(dst.Port))}) //nolint:gosec // G115: port validated 1..65535 by execpolicy
		}
	}
	return out, nil
}

// capWriter keeps the first limit bytes and counts the rest, always
// accepting the write so a chatty child is never blocked on a full pipe.
type capWriter struct {
	buf   bytes.Buffer
	limit int
	total int
}

func (w *capWriter) Write(b []byte) (int, error) {
	w.total += len(b)
	if room := w.limit - w.buf.Len(); room > 0 {
		if len(b) < room {
			room = len(b)
		}
		w.buf.Write(b[:room])
	}
	return len(b), nil
}

// logRun writes the exec.run event. Its keys are the closed set of
// internal/obs; the exit code goes in status, the destinations in
// destination_name. No argument, no output and no value.
// errCleanupAfterRefusal marks a run whose child home could not be removed on
// a path that had already been refused for another reason.
var errCleanupAfterRefusal = errors.New("child home not removed after a refusal")

func (d Deps) logRun(pl Plan, out Outcome, class runnerproto.ErrorClass, start time.Time, err error) {
	if d.Log == nil {
		return
	}
	mode := "none"
	if pl.Mode == execpolicy.NetAllowlist {
		mode = "allowlist"
	}
	var dst []string
	for _, x := range pl.Dests {
		dst = append(dst, x.String())
	}
	attrs := []any{
		"template_id", pl.TemplateID, "kind", mode, "destination_name", strings.Join(dst, ","),
		"duration_ms", time.Since(start).Milliseconds(),
	}
	if class != "" {
		status := "failed"
		if errors.Is(err, errCleanupAfterRefusal) {
			// A refusal came first; the reason text stays out.
			status = "failed_after_refusal"
		}
		d.Log.Warn("exec.run", append(attrs, "status", status, "error_class", string(class))...)
		// The reason (err) stays out of the line: it may carry a path or a name.
		return
	}
	d.Log.Info("exec.run", append(attrs, "status", "exit_"+strconv.Itoa(out.ExitCode))...)
}
