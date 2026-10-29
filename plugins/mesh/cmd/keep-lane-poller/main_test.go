package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestCheckTokenFileMode(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o600, true},
		{0o400, true},
		{0o700, false},
		{0o640, false},
		{0o604, false},
		{0o644, false},
	} {
		f := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, tc.mode); err != nil {
			t.Fatal(err)
		}
		err := checkTokenFile(f)
		if (err == nil) != tc.ok {
			t.Errorf("mode %#o: err=%v, want ok=%v", tc.mode, err, tc.ok)
		}
	}
	if checkTokenFile(filepath.Join(t.TempDir(), "missing")) == nil {
		t.Error("missing file accepted")
	}
}

// lockedBuf lets the test read what the running command has logged so far.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The canary is the token in the token file. It must not reach the command's
// output (its logger, which main points at stderr) or an error it returns:
// not when the file is refused, and not once the poller runs and its polls fail.
func TestRunOutputCarriesNoCanary(t *testing.T) {
	c := canary.New()
	t.Setenv("KEEP_URL", "https://127.0.0.1:1")
	t.Setenv("KEEP_LANE_RESTART_SCRIPT", "/abs/keep-lane-restart.sh")
	t.Setenv("KEEP_POLL_LANES", "Test")
	t.Setenv("KEEP_POLL_INTERVAL", "1s")
	file := filepath.Join(t.TempDir(), "poller.env")
	t.Setenv("KEEP_POLLER_TOKEN_FILE", file)
	write := func(content string, mode os.FileMode) {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
	}

	for name, tc := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"group readable": {"KEEP_POLLER_TOKEN=" + c.Value(0) + "\n", 0o640},
		"two lines":      {"KEEP_POLLER_TOKEN=" + c.Value(0) + "\nOTHER=" + c.Value(1) + "\n", 0o600},
		"not a token":    {c.Value(0) + " " + c.Value(1), 0o600},
	} {
		write(tc.content, tc.mode)
		var buf lockedBuf
		refused := make(chan error, 1)
		go func() { refused <- run(slog.New(slog.NewTextHandler(&buf, nil))) }()
		var err error
		select {
		case err = <-refused:
		case <-time.After(5 * time.Second): // an accepted file starts the poller, which never returns
		}
		if err == nil {
			t.Fatalf("%s: file accepted", name)
		}
		if out := buf.String() + err.Error(); c.In(out) {
			t.Errorf("%s: canary surfaced: %s", name, out)
		}
	}

	write("KEEP_POLLER_TOKEN="+c.Value(0)+"\n", 0o600)
	var buf lockedBuf
	done := make(chan error, 1)
	go func() { done <- run(slog.New(slog.NewTextHandler(&buf, nil))) }()
	// run logs "started" once its signal handler is in place, and every poll
	// against the closed port fails and is logged.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(buf.String(), "msg=started") || !strings.Contains(buf.String(), "poll failed") {
		select {
		case err := <-done:
			t.Fatalf("run returned early: %v\n%s", err, buf.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no start and failed poll logged:\n%s", buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop on SIGINT")
	}
	if c.In(buf.String()) {
		t.Fatalf("canary surfaced: %s", buf.String())
	}
}
