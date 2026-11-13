//go:build unix

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestResolveToken_RefusesSymlink is the red run for the symlink-refusal
// decision above: without O_NOFOLLOW, a symlink at the configured token
// path is followed and its target's content is read and returned as the
// bearer token — whatever that target is, not necessarily anything the
// caller meant to expose.
// scripts/check-keep-cli-mutations.sh's symlink-followed mutant reverts
// openTokenFileNoFollow to a plain os.Open and requires this test to go red.
func TestResolveToken_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("not_a_real_token"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveToken(func(string) string { return "" }, link); err == nil {
		t.Fatalf("resolveToken() over a symlink = %q, nil, want a refusal", got)
	}
}

const nonRegularHelperEnv = "KEEP_TEST_TOKEN_HELPER_PATH"

// TestResolveTokenNonRegularHelper is the child half of
// TestResolveToken_RefusesNonRegular: it returns at once unless the parent set
// nonRegularHelperEnv, so a plain `go test` run never executes it on its own.
func TestResolveTokenNonRegularHelper(t *testing.T) {
	path := os.Getenv(nonRegularHelperEnv)
	if path == "" {
		return // not a child run; returning keeps the suite free of a skip
	}
	_, err := resolveToken(func(string) string { return "" }, path)
	if err == nil {
		os.Exit(3) // read something out of a non-regular file
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		os.Exit(4) // refused, but not by the regular-file guard
	}
	os.Exit(0)
}

// TestResolveToken_RefusesNonRegular: a FIFO with no writer made the blocking
// open() wait forever, and a FIFO with a writer made the later read wait
// forever; a directory must be refused too. Each case runs in a subprocess
// under a hard deadline so a regression is a red test, not a hung one.
// scripts/check-keep-cli-mutations.sh's token-open-blocking and
// token-regular-guard-removed mutants require this test to go red.
func TestResolveToken_RefusesNonRegular(t *testing.T) {
	mkfifo := func(t *testing.T) string {
		p := filepath.Join(t.TempDir(), "token")
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]func(t *testing.T) string{
		"fifo-no-writer": mkfifo,
		"fifo-with-writer": func(t *testing.T) string {
			p := mkfifo(t)
			// O_RDWR never blocks on a FIFO and keeps a writer open for the child.
			w, err := os.OpenFile(p, os.O_RDWR, 0) //nolint:gosec // G304: p is a FIFO this test just created in t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = w.Close() })
			return p
		},
		"directory": func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "token")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			path := setup(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestResolveTokenNonRegularHelper$") //nolint:gosec // G204: re-runs this test binary, argv is a constant
			cmd.Env = append(os.Environ(), nonRegularHelperEnv+"="+path)
			cmd.WaitDelay = time.Second
			err := cmd.Run() // the child's output is never shown: it may name the path
			if ctx.Err() != nil {
				t.Fatal("resolveToken blocked on a non-regular token file, want a prompt refusal")
			}
			if err != nil {
				t.Fatalf("resolveToken did not refuse a non-regular token file with the regular-file guard (child: %v)", err)
			}
		})
	}
}
