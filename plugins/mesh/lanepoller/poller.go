// Package lanepoller pulls lane-restart requests from keep-server and runs the
// narrow restart wrapper on the host that owns the lanes. keep-server cannot
// reach that host, so the host asks: claim, run the wrapper, ack.
//
// The poller handles no secret value: the only secret it holds is its own
// restart:poll token, which is never logged or put in an error.
package lanepoller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/rotation"
)

// Ack results, as the server contract spells them.
const (
	ResultOK             = "ok"
	ResultNothingRunning = "nothing_running"
	ResultFailed         = "failed"
)

var (
	laneRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	tokRe  = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{1,512}$`)
)

const (
	maxBody    = 1 << 20
	runTimeout = 30 * time.Second
)

// Request is one claimed restart; exactly the fields the server sends.
type Request struct {
	RequestID  string `json:"request_id"`
	Lane       string `json:"lane"`
	KeyVersion string `json:"key_version"`
	// Fingerprint is the kfp1 digest of the new key, never the key.
	Fingerprint string `json:"fingerprint"`
	// ClaimToken proves this poller holds the claim; it goes back in the ack
	// and nowhere else: never logged, never in an error.
	ClaimToken string `json:"claim_token"`
}

// Runner runs the restart wrapper for one lane and returns its stdout and
// exit code. A non-nil error means the wrapper could not be run at all.
type Runner func(ctx context.Context, script, lane string) (stdout string, code int, err error)

// Config wires a Poller.
type Config struct {
	BaseURL string
	Token   string // restart:poll role token
	Script  string // absolute path of keep-lane-restart.sh
	Allow   []string
	HTTP    *http.Client
	Run     Runner
	Log     *slog.Logger
}

// Poller claims and acks restart requests.
type Poller struct {
	cfg  Config
	base *url.URL
}

// New validates cfg. The script path must be absolute so a poisoned PATH or
// working directory cannot swap the wrapper.
func New(cfg Config) (*Poller, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || !schemeOK(u) {
		return nil, errors.New("lanepoller: base URL must be https://host (http only for loopback)")
	}
	if cfg.Token == "" {
		return nil, errors.New("lanepoller: token is empty")
	}
	if !filepath.IsAbs(cfg.Script) || filepath.Clean(cfg.Script) != cfg.Script {
		return nil, errors.New("lanepoller: script path must be absolute and clean")
	}
	if len(cfg.Allow) == 0 {
		return nil, errors.New("lanepoller: lane allowlist is empty")
	}
	for _, l := range cfg.Allow {
		if !laneRe.MatchString(l) {
			return nil, errors.New("lanepoller: allowlist entries must match [A-Za-z0-9_]{1,64}")
		}
	}
	// No redirects: the bearer and claim token must not follow a hop to another
	// scheme, host or port. A supplied client keeps its transport and timeout, but
	// is copied so its redirect policy is ours and the caller's client is untouched.
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 20 * time.Second}
	} else {
		c := *cfg.HTTP
		cfg.HTTP = &c
	}
	cfg.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if cfg.Run == nil {
		cfg.Run = ExecRunner
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Poller{cfg: cfg, base: u}, nil
}

// ExecRunner runs the wrapper with the lane as its only argument and an empty
// environment apart from PATH, so no lane or operator secret is inherited.
func ExecRunner(ctx context.Context, script, lane string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, script, lane) //nolint:gosec // script is operator config, checked absolute in New; lane is allowlisted
	cmd.WaitDelay = 2 * time.Second               // a child holding stdout open must not outlive the timeout
	cmd.Env = []string{"PATH=/usr/bin:/bin:/opt/homebrew/bin", "HOME=" + homeOf()}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0, nil
	case errors.As(err, &ee):
		return out.String(), ee.ExitCode(), nil
	default:
		return "", -1, err
	}
}

// Run polls every interval until ctx ends. A failing tick is logged and the
// loop goes on: an unreachable server must not stop the poller.
func (p *Poller) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := p.Once(ctx); err != nil && ctx.Err() == nil {
			p.cfg.Log.Warn("poll failed", "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once claims a batch and handles every request in it.
func (p *Poller) Once(ctx context.Context) error {
	var reqs []Request
	if err := p.call(ctx, "/v1/restarts/claim", nil, &reqs); err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	var firstErr error
	for _, r := range reqs {
		if err := p.handle(ctx, r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (p *Poller) handle(ctx context.Context, r Request) error {
	id, err := uuidLike(r.RequestID)
	if err != nil {
		p.cfg.Log.Warn("bad request id, ignored")
		return nil // cannot ack an id we cannot put in a path
	}
	r.RequestID = id.String()
	if !tokRe.MatchString(r.ClaimToken) {
		p.cfg.Log.Warn("claim without usable claim token, ignored", "request_id", r.RequestID)
		return nil // the server would refuse the ack, and the restart is not ours to run
	}
	// Server fields are logged only when they have the expected shape.
	log := p.cfg.Log.With("lane", shaped(laneRe, r.Lane), "request_id", r.RequestID,
		"key_version", shapedBy(rotation.ValidKeyID, r.KeyVersion), "fingerprint", shapedBy(fingerprint.Valid, r.Fingerprint))
	result := ResultFailed
	if !slices.Contains(p.cfg.Allow, r.Lane) {
		log.Warn("lane outside allowlist, wrapper not run")
	} else {
		out, code, err := p.cfg.Run(ctx, p.cfg.Script, r.Lane)
		result = classify(out, code, err)
		log.Info("wrapper finished", "exit", code, "result", result)
	}
	body := map[string]string{"result": result, "claim_token": r.ClaimToken}
	if err := p.call(ctx, "/v1/restarts/"+r.RequestID+"/ack", body, nil); err != nil {
		log.Warn("ack failed", "err", err.Error())
		return fmt.Errorf("ack: %w", err)
	}
	return nil
}

// classify maps the wrapper outcome to an ack result. The wrapper exits 0 both
// when it closed a session and when none was running; it says which on stdout.
func classify(stdout string, code int, err error) string {
	if err != nil || code != 0 {
		return ResultFailed
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	nothing := false
	for _, l := range lines {
		if strings.Contains(l, "session mr-") && strings.Contains(l, "closed") {
			return ResultOK
		}
		if strings.Contains(l, "(nothing running)") {
			nothing = true
		}
	}
	if nothing {
		return ResultNothingRunning
	}
	return ResultFailed // exit 0 with unrecognised output is not proof of a restart
}

func shaped(re *regexp.Regexp, v string) string { return shapedBy(re.MatchString, v) }

// shapedBy logs v only when ok accepts it. The version and fingerprint use the
// validators keep-server itself applies (a Mesh key id, a kfp1 digest), so the
// log carries what the server sends and nothing of another shape.
func shapedBy(ok func(string) bool, v string) string {
	if ok(v) {
		return v
	}
	return "invalid"
}

func schemeOK(u *url.URL) bool {
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// transportCategory names a client error without quoting it: the standard
// client echoes server-controlled text (a Location header) in its messages.
func transportCategory(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case ctx.Err() != nil:
		return "canceled"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.As(err, new(*net.OpError)):
		return "connection failed"
	default:
		return "request failed"
	}
}

// call POSTs JSON and decodes a JSON answer into out when out is not nil.
// Errors carry the path and status only, never a response body.
func (p *Poller) call(ctx context.Context, path string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base.JoinPath(path).String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.cfg.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %s", path, transportCategory(ctx, err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return fmt.Errorf("%s: undecodable answer", path)
	}
	return nil
}
