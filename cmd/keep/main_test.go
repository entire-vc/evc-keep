package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestRunLoginSubcommandRejectsTokenAfterFlags: flag.FlagSet.Parse stops at
// the first non-flag argument, so `keep login --token-file P TOKEN` never
// reaches TOKEN through fs.Args() unless runLoginSubcommand checks for it.
// Pre-fix, the leftover TOKEN was silently ignored, the command fell
// through to the stdin path with no ps/shell-history warning at all, and
// (with stdin empty, as here) failed later with the unrelated "token must
// not be empty" — never naming the real problem. This must instead fail
// loudly about the unconsumed argument, and — the leftover argument IS the
// token — the error text must name only the argument COUNT, never the
// argument itself: a literal-string assertion here would have missed the
// %v-on-extra leak (the token printed straight to stderr) that a canary
// alone can catch, so the token used in this test is a canary value, and
// the assertion checks for its absence, not the presence of some other
// substring.
func TestRunLoginSubcommandRejectsTokenAfterFlags(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	c := canary.New()
	token := c.Value(0)
	var stderr bytes.Buffer
	getenv := func(string) string { return "" }

	code := runLoginSubcommand([]string{"--token-file", tokenFile, token}, strings.NewReader(""), &stderr, getenv)

	if code == 0 {
		t.Fatalf("exit 0, want a non-zero exit for an unconsumed trailing argument; stderr=%q", stderr.String())
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "unexpected argument") {
		t.Fatalf("stderr = %q, want it to name the rejected leftover argument instead of falling through to the stdin path silently", stderr.String())
	}
	if c.In(stderr.String()) {
		t.Fatalf("stderr contains the rejected token itself, want only its count: %q", stderr.String())
	}
	// Positive control: prove the canary check above is actually capable of
	// catching a leak, not just structurally unable to trigger. Without
	// this, a check that can never fail is indistinguishable from one that
	// always passes for the right reason.
	if !c.In(fmt.Sprintf("keep login: unexpected argument(s) [%s]", token)) {
		t.Fatal("canary.In doesn't detect its own value in a Printf-style leak — the assertion above would never catch this regression")
	}
	if _, err := os.Stat(tokenFile); err == nil {
		t.Fatal("token file was written despite the leftover positional argument being rejected")
	}
}

// TestRunLoginSubcommandLeadingDashTokenNotEchoed: a token that starts with
// "-" is not a positional argument to flag.FlagSet.Parse but an unknown
// flag, and the stdlib's own parse-error text ("flag provided but not
// defined: -TOKEN") embeds it verbatim on the FlagSet's output. The login
// FlagSet must not write that text anywhere; our own error names only that
// parsing failed.
func TestRunLoginSubcommandLeadingDashTokenNotEchoed(t *testing.T) {
	for _, withFlag := range []bool{false, true} {
		tokenFile := filepath.Join(t.TempDir(), "token")
		c := canary.New()
		token := "-" + c.Value(0)
		args := []string{token}
		if withFlag {
			args = []string{"--token-file", tokenFile, token}
		}
		var stderr bytes.Buffer
		getenv := func(string) string { return "" }

		code := runLoginSubcommand(args, strings.NewReader(""), &stderr, getenv)

		if code == 0 {
			t.Fatalf("exit 0, want non-zero for an unparseable argument; stderr=%q", stderr.String())
		}
		if !strings.Contains(stderr.String(), "keep login:") {
			t.Fatalf("stderr = %q, want our own keep login error naming the parse failure", stderr.String())
		}
		if c.In(stderr.String()) {
			t.Fatalf("stderr contains the leading-dash token, want no argument values: %q", stderr.String())
		}
		// Positive control: the stdlib's text is exactly the leak shape
		// this test must be able to catch.
		if !c.In(fmt.Sprintf("flag provided but not defined: %s", token)) {
			t.Fatal("canary.In doesn't detect its own value in the stdlib parse-error shape — the assertion above would never catch this regression")
		}
		if _, err := os.Stat(tokenFile); err == nil {
			t.Fatal("token file was written despite the parse failure")
		}
	}
}

// TestRunLoginSubcommandLeadingDashTokenNamesCause: the refusal for an
// argument starting with "-" must tell the user why (it was read as a flag,
// not as a token) and what to do (pipe it on stdin), without the argument.
func TestRunLoginSubcommandLeadingDashTokenNamesCause(t *testing.T) {
	for _, withFlag := range []bool{false, true} {
		tokenFile := filepath.Join(t.TempDir(), "token")
		c := canary.New()
		token := "-" + c.Value(0)
		args := []string{token}
		if withFlag {
			args = []string{"--token-file", tokenFile, token}
		}
		var stderr bytes.Buffer

		code := runLoginSubcommand(args, strings.NewReader(""), &stderr, func(string) string { return "" })

		if code != 2 {
			t.Fatalf("exit %d, want 2; stderr=%q", code, stderr.String())
		}
		for _, want := range []string{`starting with "-"`, "not a known flag", "stdin"} {
			if !strings.Contains(stderr.String(), want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), want)
			}
		}
		if c.In(stderr.String()) {
			t.Fatalf("stderr contains the leading-dash token: %q", stderr.String())
		}
	}
	// An ordinary typo'd flag gets the same cause-naming message and no value.
	var stderr bytes.Buffer
	if code := runLoginSubcommand([]string{"--bogus"}, strings.NewReader(""), &stderr, func(string) string { return "" }); code != 2 || !strings.Contains(stderr.String(), "not a known flag") {
		t.Fatalf("unknown flag: exit %d stderr=%q", code, stderr.String())
	}
}

// TestRunLoginSubcommandPlainPositionalStillWorks: the ordinary
// `keep login TOKEN --token-file P` form (token before any flags) must
// still work exactly as before — this fix only closes the flag-then-token
// order, it must not start rejecting the documented one.
func TestRunLoginSubcommandPlainPositionalStillWorks(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	var stderr bytes.Buffer
	getenv := func(string) string { return "" }

	code := runLoginSubcommand([]string{"sometoken", "--token-file", tokenFile}, strings.NewReader(""), &stderr, getenv)

	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr=%q", code, stderr.String())
	}
	got, err := os.ReadFile(tokenFile) //nolint:gosec // G304: tokenFile is this test's own t.TempDir() path
	if err != nil {
		t.Fatalf("token file was not written: %v", err)
	}
	if strings.TrimSpace(string(got)) != "sometoken" {
		t.Fatalf("token file content = %q, want %q", got, "sometoken")
	}
}

func TestHelpAndParseErrorsDoNotPrintKeepServerPassword(t *testing.T) {
	const pw = "CANARYPW-7f3a" //nolint:gosec // G101: a fake canary, not a credential
	env := map[string]string{"KEEP_SERVER": "https://alice:" + pw + "@keep.example", "KEEP_ORG": "o"}
	getenv := func(k string) string { return env[k] }
	for _, args := range [][]string{{"list", "-h"}, {"meta", "x", "--bogus"}} {
		var out, errb bytes.Buffer
		_ = run(args, strings.NewReader(""), &out, &errb, getenv)
		// positive control: some static help or error text was printed
		if errb.Len() == 0 {
			t.Fatalf("%v: no help or error text printed (%d bytes); the test would pass vacuously", args, errb.Len())
		}
		if strings.Contains(out.String()+errb.String(), pw) {
			t.Fatalf("%v: KEEP_SERVER password reached the terminal", args)
		}
	}
}
