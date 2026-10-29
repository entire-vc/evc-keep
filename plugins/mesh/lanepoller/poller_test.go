package lanepoller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/plugins/mesh/lanepoller"
	"github.com/google/uuid"
)

type ack struct{ id, result, token string }

// stub is a keep-server stand-in: it hands out queued requests once and
// records acks and the bearer it saw.
type stub struct {
	mu     sync.Mutex
	queue  []map[string]any
	acks   []ack
	claims int
	bearer string
	fail   int // claim answers 500 with this body while > 0
	body   string
	srv    *httptest.Server
}

func newStub(t *testing.T) *stub {
	s := &stub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.bearer = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/v1/restarts/claim":
			s.claims++
			if s.fail > 0 {
				s.fail--
				http.Error(w, s.body, 500)
				return
			}
			q := s.queue
			s.queue = nil
			if q == nil {
				q = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(q)
		case strings.HasPrefix(r.URL.Path, "/v1/restarts/") && strings.HasSuffix(r.URL.Path, "/ack"):
			var b struct {
				Result     string
				ClaimToken string `json:"claim_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/restarts/"), "/ack")
			s.acks = append(s.acks, ack{id, b.Result, b.ClaimToken})
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stub) push(lane, extra string) string {
	id := uuid.NewString()
	e := map[string]any{"request_id": id, "lane": lane, "key_version": uuid.NewString(), "fingerprint": "kfp1:k1:abcdefghijklmnop", "claim_token": "ct-" + id}
	if extra != "" {
		e["note"] = extra
	}
	s.queue = append(s.queue, e)
	return id
}

type runs struct {
	mu    sync.Mutex
	lanes []string
	out   string
	code  int
	err   error
}

func (r *runs) run(_ context.Context, script, lane string) (string, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if script != "/abs/keep-lane-restart.sh" {
		return "", 0, errors.New("wrong script")
	}
	r.lanes = append(r.lanes, lane)
	return r.out, r.code, r.err
}

func newPoller(t *testing.T, s *stub, r *runs, token string, buf *bytes.Buffer, allow ...string) *lanepoller.Poller {
	t.Helper()
	if len(allow) == 0 {
		allow = []string{"Hugh", "Test"}
	}
	p, err := lanepoller.New(lanepoller.Config{
		BaseURL: s.srv.URL, Token: token, Script: "/abs/keep-lane-restart.sh", Allow: allow,
		Run: r.run, Log: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClaimRunAck(t *testing.T) {
	cases := []struct {
		name string
		out  string
		code int
		want string
	}{
		{"closed", "Test: session mr-Test closed\nTest: online in runner status\n", 0, lanepoller.ResultOK},
		{"nothing", "Test: no session mr-Test (nothing running)\n", 0, lanepoller.ResultNothingRunning},
		{"exit2", "refused\n", 2, lanepoller.ResultFailed},
		{"exit2 with ok-looking output", "Test: session mr-Test closed\n", 2, lanepoller.ResultFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, r := newStub(t), &runs{out: c.out, code: c.code}
			id := s.push("Test", "")
			var buf bytes.Buffer
			if err := newPoller(t, s, r, "tok", &buf).Once(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(r.lanes) != 1 || r.lanes[0] != "Test" {
				t.Fatalf("wrapper runs = %v, want exactly [Test]", r.lanes)
			}
			if len(s.acks) != 1 || s.acks[0] != (ack{id, c.want, "ct-" + id}) {
				t.Fatalf("acks = %v, want %s %s", s.acks, id, c.want)
			}
			if s.bearer != "Bearer tok" {
				t.Fatal("token not sent as bearer")
			}
		})
	}
}

func TestRunnerCannotStartAcksFailed(t *testing.T) {
	s, r := newStub(t), &runs{err: errors.New("boom")}
	id := s.push("Hugh", "")
	if err := newPoller(t, s, r, "tok", &bytes.Buffer{}).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.acks) != 1 || s.acks[0] != (ack{id, lanepoller.ResultFailed, "ct-" + id}) {
		t.Fatalf("acks = %v", s.acks)
	}
}

func TestLaneOutsideAllowlistNeverRunsWrapper(t *testing.T) {
	s, r := newStub(t), &runs{}
	id := s.push("Calvin", "")
	s.push("../Test", "")
	if err := newPoller(t, s, r, "tok", &bytes.Buffer{}).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.lanes) != 0 {
		t.Fatalf("wrapper ran for %v", r.lanes)
	}
	if len(s.acks) != 2 || s.acks[0] != (ack{id, lanepoller.ResultFailed, "ct-" + id}) || s.acks[1].result != lanepoller.ResultFailed {
		t.Fatalf("acks = %v", s.acks)
	}
}

func TestBadRequestIDIsIgnored(t *testing.T) {
	s, r := newStub(t), &runs{}
	s.queue = []map[string]any{{"request_id": "../../x", "lane": "Test"}}
	if err := newPoller(t, s, r, "tok", &bytes.Buffer{}).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.lanes) != 0 || len(s.acks) != 0 {
		t.Fatalf("runs %v acks %v", r.lanes, s.acks)
	}
}

func TestServerDownPollerStaysAliveAndRetries(t *testing.T) {
	s, r := newStub(t), &runs{out: "Test: no session mr-Test (nothing running)\n"}
	s.fail = 2
	s.body = "down"
	id := s.push("Test", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	p := newPoller(t, s, r, "tok", &bytes.Buffer{})
	go func() { p.Run(ctx, 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.acks)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no ack after server recovered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	// The server may still be inside a handler after Run returns.
	s.mu.Lock()
	claims, acks := s.claims, append([]ack(nil), s.acks...)
	s.mu.Unlock()
	if claims < 3 || acks[0].id != id {
		t.Fatalf("claims %d acks %v", claims, acks)
	}

	// An unreachable server (closed listener) is an error, not a crash.
	s.srv.Close()
	if err := newPoller(t, s, r, "tok", &bytes.Buffer{}).Once(context.Background()); err == nil {
		t.Fatal("want error for unreachable server")
	}
}

// The canary is the token, a stray field in the claim answer and the body of
// an error answer. None may reach a log line or an error text.
func TestCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	s, r := newStub(t), &runs{out: c.Value(3) + " (nothing running)\n"}
	s.push("Test", c.Value(1))
	s.push("Evil", c.Value(1))
	var buf bytes.Buffer
	p := newPoller(t, s, r, c.Value(0), &buf)
	var texts []string
	if err := p.Once(context.Background()); err != nil {
		texts = append(texts, err.Error())
	}
	s.fail, s.body = 1, c.Value(2)
	if err := p.Once(context.Background()); err == nil {
		t.Fatal("want error")
	} else {
		texts = append(texts, err.Error())
	}
	if len(s.acks) == 0 || buf.Len() == 0 {
		t.Fatal("test saw no traffic or no logs")
	}
	all := buf.String() + strings.Join(texts, "\n")
	if c.In(all) {
		t.Fatalf("canary surfaced: %s", all)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	ok := lanepoller.Config{BaseURL: "https://k.example", Token: "t", Script: "/a", Allow: []string{"Test"}}
	if _, err := lanepoller.New(ok); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*lanepoller.Config){
		"relative script": func(c *lanepoller.Config) { c.Script = "keep-lane-restart.sh" },
		"empty token":     func(c *lanepoller.Config) { c.Token = "" },
		"empty allow":     func(c *lanepoller.Config) { c.Allow = nil },
		"bad url":         func(c *lanepoller.Config) { c.BaseURL = "ftp://x" },
		"plain http":      func(c *lanepoller.Config) { c.BaseURL = "http://k.example" },
		"empty lane":      func(c *lanepoller.Config) { c.Allow = []string{"Test", ""} },
		"dash lane":       func(c *lanepoller.Config) { c.Allow = []string{"-x"} },
		"unclean script":  func(c *lanepoller.Config) { c.Script = "/a/../b" },
	} {
		c := ok
		mut(&c)
		if _, err := lanepoller.New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestExecRunnerPassesLaneAndEmptyEnv(t *testing.T) {
	t.Setenv("KEEP_CANARY_ENV", "leaky")
	dir := t.TempDir()
	sh := filepath.Join(dir, "w.sh")
	script := "#!/bin/sh\necho \"lane=$1 env=${KEEP_CANARY_ENV:-unset}\"\nexit 0\n"
	if err := os.WriteFile(sh, []byte(script), 0o600); err != nil || os.Chmod(sh, 0o700) != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	out, code, err := lanepoller.ExecRunner(context.Background(), sh, "Test")
	if err != nil || code != 0 || strings.TrimSpace(out) != "lane=Test env=unset" {
		t.Fatalf("out %q code %d err %v", out, code, err)
	}
	if err := os.WriteFile(sh, []byte("#!/bin/sh\nexit 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := lanepoller.ExecRunner(context.Background(), sh, "Test"); code != 2 {
		t.Fatalf("code %d", code)
	}
}

func TestExecRunnerReturnsWhenChildHoldsStdout(t *testing.T) {
	sh := filepath.Join(t.TempDir(), "w.sh")
	if err := os.WriteFile(sh, []byte("#!/bin/sh\n(sleep 20 &)\necho done\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sh, 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	start := time.Now()
	_, _, _ = lanepoller.ExecRunner(context.Background(), sh, "Test")
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("ExecRunner blocked %s on a lingering child", d)
	}
}

func TestServerFieldsAreLoggedOnlyWhenShaped(t *testing.T) {
	c := canary.New()
	s, r := newStub(t), &runs{out: "Test: session mr-Test closed\n"}
	s.queue = []map[string]any{{"request_id": uuid.NewString(), "lane": "Test",
		"key_version": c.Value(1), "fingerprint": c.Value(2), "claim_token": "ct-1"}}
	var buf bytes.Buffer
	if err := newPoller(t, s, r, "tok", &buf).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.acks) != 1 || buf.Len() == 0 || c.In(buf.String()) {
		t.Fatalf("acks %v, log %q", s.acks, buf.String())
	}
}

// The version and fingerprint keep-server really sends (a Mesh key id and a
// kfp1 digest) reach the log as they are; a shape check that rejects them
// would leave the journal without the key the lane must be running.
func TestServerShapedFieldsAreLogged(t *testing.T) {
	ver, fp := uuid.NewString(), "kfp1:k1:abcdefghijklmnop"
	if !rotation.ValidKeyID(ver) || !fingerprint.Valid(fp) {
		t.Fatalf("fixture is not in the server's shape: %q %q", ver, fp)
	}
	s, r := newStub(t), &runs{out: "Test: no session mr-Test (nothing running)\n"}
	s.queue = []map[string]any{{"request_id": uuid.NewString(), "lane": "Test",
		"key_version": ver, "fingerprint": fp, "claim_token": "ct-1"}}
	var buf bytes.Buffer
	if err := newPoller(t, s, r, "tok", &buf).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"key_version=" + ver, "fingerprint=" + fp} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log lacks %s: %q", want, buf.String())
		}
	}
}

// A lane name from the server is logged only in the lane shape, even when it
// is refused by the allowlist.
func TestLaneIsLoggedOnlyWhenShaped(t *testing.T) {
	c := canary.New()
	s, r := newStub(t), &runs{out: "(nothing running)\n"}
	s.push("Test", "")
	s.queue[0]["lane"] = c.Value(3)
	var buf bytes.Buffer
	if err := newPoller(t, s, r, "tok", &buf).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.lanes) != 0 || buf.Len() == 0 || c.In(buf.String()) {
		t.Fatalf("wrapper runs %v, log %q", r.lanes, buf.String())
	}
}

// A request id that cannot go into the ack path is neither run nor acked.
func TestBadRequestIDIsNotRunNorAcked(t *testing.T) {
	for _, id := range []any{nil, "", "not-a-uuid", "../claim"} {
		s, r := newStub(t), &runs{out: "(nothing running)\n"}
		s.push("Test", "")
		if id == nil {
			delete(s.queue[0], "request_id")
		} else {
			s.queue[0]["request_id"] = id
		}
		if err := newPoller(t, s, r, "tok", &bytes.Buffer{}).Once(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(r.lanes) != 0 || len(s.acks) != 0 {
			t.Fatalf("id %q: wrapper runs %v, acks %v; want none", id, r.lanes, s.acks)
		}
	}
}

func TestUnrecognisedOutputIsNotOK(t *testing.T) {
	s, r := newStub(t), &runs{out: "something else\n"}
	s.push("Test", "")
	if err := newPoller(t, s, r, "tok", &bytes.Buffer{}).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.acks[0].result != lanepoller.ResultFailed {
		t.Fatalf("acks %v", s.acks)
	}
}

// A malformed Location in a redirect makes the HTTP client quote that header
// in its error. A hostile or broken server may put the bearer there; neither
// the claim nor the ack error may carry it.
func TestMalformedRedirectLocationDoesNotLeakIntoErrors(t *testing.T) {
	c := canary.New()
	for _, path := range []string{"claim", "ack"} {
		t.Run(path, func(t *testing.T) {
			var claimed bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if path == "ack" && strings.HasSuffix(r.URL.Path, "/claim") && !claimed {
					claimed = true
					_ = json.NewEncoder(w).Encode([]map[string]any{{"request_id": uuid.NewString(), "lane": "Test", "claim_token": c.Value(5)}})
					return
				}
				w.Header().Set("Location", "http://["+bearer+"/"+c.Value(5))
				w.WriteHeader(http.StatusFound)
			}))
			t.Cleanup(srv.Close)
			var buf bytes.Buffer
			p, err := lanepoller.New(lanepoller.Config{
				BaseURL: srv.URL, Token: c.Value(0), Script: "/abs/keep-lane-restart.sh", Allow: []string{"Test"},
				Run: (&runs{out: "(nothing running)\n"}).run,
				Log: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
			})
			if err != nil {
				t.Fatal(err)
			}
			err = p.Once(context.Background())
			if err == nil {
				t.Fatal("want error")
			}
			if all := err.Error() + "\n" + buf.String(); c.In(all) {
				t.Fatalf("token reflected in error or log (value suppressed)")
			}
		})
	}
}

// The claim token goes back in the ack, and only there.
func TestAckCarriesClaimTokenWithoutLeakingIt(t *testing.T) {
	c := canary.New()
	s, r := newStub(t), &runs{out: "(nothing running)\n"}
	id := s.push("Test", "")
	s.queue[0]["claim_token"] = c.Value(4)
	var buf bytes.Buffer
	p := newPoller(t, s, r, "tok", &buf)
	if err := p.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.acks) != 1 || s.acks[0].id != id || s.acks[0].token != c.Value(4) {
		t.Fatalf("ack did not carry the claim token (value suppressed): %d acks", len(s.acks))
	}
	if buf.Len() == 0 || c.In(buf.String()) {
		t.Fatal("claim token in log, or no log produced")
	}
}

func TestClaimWithoutUsableTokenIsNotRunNorAcked(t *testing.T) {
	for _, tok := range []any{nil, "", "has space", strings.Repeat("a", 513)} {
		s, r := newStub(t), &runs{out: "(nothing running)\n"}
		s.push("Test", "")
		if tok == nil {
			delete(s.queue[0], "claim_token")
		} else {
			s.queue[0]["claim_token"] = tok
		}
		var buf bytes.Buffer
		if err := newPoller(t, s, r, "tok", &buf).Once(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(r.lanes) != 0 || len(s.acks) != 0 {
			t.Fatalf("token %q: wrapper runs %v, acks %v; want none", tok, r.lanes, s.acks)
		}
	}
}

// A caller-supplied client must not make the poller follow redirects: the
// bearer and the claim token would reach whatever the server points at.
func TestSuppliedClientCannotForwardSecrets(t *testing.T) {
	c := canary.New()
	for _, mode := range []string{"claim", "ack", "ack-crosshost"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var sinkHits int
			var leaked bool
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := new(bytes.Buffer)
				_, _ = body.ReadFrom(r.Body)
				mu.Lock()
				defer mu.Unlock()
				sinkHits++
				if c.In(r.Header.Get("Authorization")) || c.In(body.String()) {
					leaked = true
				}
			}))
			t.Cleanup(sink.Close)
			dest := sink.URL
			if mode == "ack-crosshost" {
				dest = strings.Replace(sink.URL, "127.0.0.1", "localhost", 1)
			}
			var claimed bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode != "claim" && strings.HasSuffix(r.URL.Path, "/claim") && !claimed {
					claimed = true
					_ = json.NewEncoder(w).Encode([]map[string]any{{"request_id": uuid.NewString(), "lane": "Test", "claim_token": c.Value(5)}})
					return
				}
				http.Redirect(w, r, dest+"/sink", http.StatusTemporaryRedirect)
			}))
			t.Cleanup(srv.Close)
			var buf bytes.Buffer
			client := &http.Client{Timeout: time.Second}
			p, err := lanepoller.New(lanepoller.Config{
				BaseURL: srv.URL, Token: c.Value(0), Script: "/abs/keep-lane-restart.sh", Allow: []string{"Test"},
				HTTP: client, Run: (&runs{out: "(nothing running)\n"}).run,
				Log: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
			})
			if err != nil {
				t.Fatal(err)
			}
			err = p.Once(context.Background())
			if err == nil {
				t.Fatal("want error on redirect")
			}
			mu.Lock()
			defer mu.Unlock()
			if sinkHits != 0 || leaked {
				t.Fatalf("redirect followed: sink hits=%d credential leaked=%v (values suppressed)", sinkHits, leaked)
			}
			if client.CheckRedirect != nil {
				t.Fatal("caller's client was modified")
			}
			if all := err.Error() + "\n" + buf.String(); c.In(all) {
				t.Fatalf("token reflected in error or log (value suppressed)")
			}
		})
	}
}
