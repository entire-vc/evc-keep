package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/internal/runner/execrun"
	"github.com/entire-vc/evc-keep/internal/runner/loop"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

var identityRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// identityFromCert reads the runner's own org and runner id from its
// enrollment certificate (organization and common name), never from a job.
func identityFromCert(der []byte) (runnerproto.Identity, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil || len(cert.Subject.Organization) != 1 {
		return runnerproto.Identity{}, errors.New("certificate carries no runner identity")
	}
	id := runnerproto.Identity{OrgID: cert.Subject.Organization[0], RunnerID: cert.Subject.CommonName}
	if !identityRe.MatchString(id.OrgID) || !identityRe.MatchString(id.RunnerID) {
		return runnerproto.Identity{}, errors.New("certificate carries no runner identity")
	}
	return id, nil
}

// runRun is the execution loop. Every failure prints a fixed message: an
// argument, a path or a lower-level error text is never reflected.
func runRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(discard{})
	dir := fs.String("cred-dir", defaultCredDir, "directory holding the enrollment credential")
	policyPath := fs.String("policy", "", "path to the host policy")
	server := fs.String("server", os.Getenv("KEEP_SERVER"), "Keep Server's runner (mTLS) listener base URL")
	serverCA := fs.String("server-ca", os.Getenv("KEEP_SERVER_CA"), "PEM CA bundle to trust for -server instead of the system trust store")
	stateDir := fs.String("state-dir", "", "directory for the replay journal and the result outbox (default: <cred-dir>/state)")
	execUID := fs.Uint("exec-uid", 0, "account exec_with_secret children run as: a dedicated one, not shared with other services and never 0 (required when the policy allows exec)")
	execGID := fs.Uint("exec-gid", 0, "group exec_with_secret children run as (required when the policy allows exec)")
	execHomeDir := fs.String("exec-home", "", "empty directory in which exec_with_secret makes a private HOME and cwd for every run and removes it after; owned by the runner, not writable by group or others, enterable by -exec-uid (required when the policy allows exec)")
	once := fs.Bool("once", false, "poll once, run at most one job, send its result and exit")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "keep-runner run: invalid arguments")
		return 2
	}
	if *policyPath == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "keep-runner run: -policy and -server (or KEEP_SERVER) are required")
		return 2
	}
	state := *stateDir
	if state == "" {
		state = filepath.Join(*dir, "state")
	}
	fatal := func(what string) int {
		fmt.Fprintf(os.Stderr, "keep-runner run: %s\n", what)
		return 1
	}

	cred, err := runner.Load(*dir)
	if err != nil {
		return fatal("credential is missing or insecure")
	}
	defer clear(cred.Key)
	if cred.DeliveryKey == nil {
		return fatal("credential has no delivery key; re-enroll")
	}
	me, err := identityFromCert(cred.CertDER)
	if err != nil {
		return fatal("credential carries no runner identity")
	}
	policy, err := runnerproto.LoadHostPolicy(*policyPath, os.Getuid())
	if err != nil {
		return fatal("invalid local policy or insecure policy file")
	}
	log := obs.New(os.Stderr)
	// Warn, do not stop: the other rules still work. keep-runner check names
	// the component; the closed log keys cannot carry the path.
	if err := runnerproto.CheckPrefixesOnHost(policy); err != nil {
		log.Warn("host policy has a path prefix through a symlink or a file; jobs under it will be denied, run keep-runner check",
			"error_class", "policy_prefix_not_plain")
	}
	pool, err := loadServerCAPool(*serverCA)
	if err != nil {
		return fatal("server CA bundle is unreadable")
	}
	tr, err := loop.NewHTTPTransport(*server, cred, pool)
	if err != nil {
		return fatal("-server must be an https:// URL")
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return fatal("state directory is unusable")
	}
	outbox, err := loop.OpenOutbox(filepath.Join(state, "outbox"))
	if err != nil {
		return fatal("outbox is unusable")
	}
	journal, err := runnerproto.OpenFileJournal(filepath.Join(state, "replay.journal"), time.Now())
	if err != nil {
		return fatal("replay journal is unusable")
	}
	defer func() { _ = journal.Close() }()

	var execDeps *execrun.Deps
	if policy.AllowExec {
		var msg string
		if execDeps, msg = execSetup(*execUID, *execGID, *execHomeDir); msg != "" {
			return fatal(msg)
		}
	}

	r := &loop.Runner{
		Exec:      execDeps,
		Transport: tr,
		Me:        me,
		Keys:      runnerproto.TrustedKeys{cred.SignKeyID: ed25519.PublicKey(cred.SignPubKey)},
		Policy:    policy,
		Journal:   journal,
		Limiter:   runnerproto.NewLimiter(policy),
		Delivery:  cred.DeliveryKey,
		Outbox:    outbox,
		Log:       log,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if err := r.Drain(ctx); err != nil {
			return fatal("could not send pending results")
		}
		if _, err := r.Once(ctx); err != nil {
			return fatal("poll or result send failed")
		}
		return 0
	}
	if err := r.Run(ctx); err != nil {
		return fatal("stopped on an unusable outbox")
	}
	return 0
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
