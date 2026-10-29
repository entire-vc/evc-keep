// Package deploy holds the deployment artifacts (container build, systemd
// unit, example configuration). The tests here are the leak test for them:
// nothing shipped for deployment carries a configuration value, and a failed
// start prints none.
package deploy

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/cmd/keep-server/app"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// knownNames is every variable keep-server reads in a deployment; the example
// file may list these and nothing else.
var knownNames = map[string]bool{
	"KEEP_DATABASE_URL": true, "KEEP_ROOT_KEY_FILE": true, "KEEP_ROOT_KEY_ID": true,
	"KEEP_PUBLIC_URL": true, "KEEP_SERVER_TLS_CERT_FILE": true,
	"KEEP_SERVER_TLS_KEY_FILE": true, "KEEP_HTTP_ADDR": true, "KEEP_RUNNER_ADDR": true,
	"KEEP_TRUSTED_PROXIES": true,
}

// addressValues are the settings that name addresses, never a credential; the
// example and the runbook show their recommended value.
var addressValues = map[string]bool{"KEEP_TRUSTED_PROXIES": true}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The example configuration is names only: every assignment has an empty value.
func TestEnvExampleHasNamesOnly(t *testing.T) {
	for _, problem := range envExampleProblems(read(t, "keep-server.env.example")) {
		t.Error(problem)
	}
}

func envExampleProblems(text string) (problems []string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || !knownNames[name] {
			problems = append(problems, "unexpected line in env example: "+name)
			continue
		}
		if value != "" && !addressValues[name] {
			problems = append(problems, name+" carries a value in the example; names only")
		}
	}
	return problems
}

// Neither the image build, the unit nor the runbook assigns a KEEP_* value
// other than a listen address, a key id or a documented placeholder-free flag.
func TestNoValuesInBuildUnitOrRunbook(t *testing.T) {
	assign := regexp.MustCompile(`KEEP_[A-Z_]+=([^\s` + "`" + `"']+)`)
	allowed := map[string]bool{"KEEP_HTTP_ADDR": true, "KEEP_RUNNER_ADDR": true, "KEEP_ROOT_KEY_ID": true, "KEEP_TRUSTED_PROXIES": true}
	for _, f := range []string{"../Dockerfile", "keep-server.service", "../docs/deploy.md"} {
		for _, m := range assign.FindAllStringSubmatch(read(t, f), -1) {
			name := strings.SplitN(m[0], "=", 2)[0]
			if !allowed[name] {
				t.Errorf("%s assigns %s a value", f, name)
			}
		}
	}
	if regexp.MustCompile(`(?m)^\s*(ENV|ARG)\s+KEEP_`).MatchString(read(t, "../Dockerfile")) {
		t.Error("Dockerfile bakes a KEEP_* setting into the image")
	}
}

// The runbook never passes the database URL as a command-line argument: argv is
// readable by every local user.
func TestRunbookKeepsDBURLOutOfArgv(t *testing.T) {
	if p := urlInArgv(read(t, "../docs/deploy.md")); len(p) > 0 {
		t.Errorf("runbook passes the database URL in argv: %v", p)
	}
}

// Red run: the former rollback command and a stray "migrate up" with the URL are caught.
func TestArgvCheckCatchesURL(t *testing.T) {
	bad := "goose -dir d postgres \"$KEEP_DATABASE_URL\" down-to 3\n"
	if len(urlInArgv(bad)) == 0 {
		t.Error("argv check missed a URL argument")
	}
	if len(urlInArgv("GOOSE_DBSTRING=\"$KEEP_DATABASE_URL\" exec goose down-to 3\n")) != 0 {
		t.Error("argv check flagged the environment form")
	}
}

func urlInArgv(doc string) []string {
	var out []string
	re := regexp.MustCompile(`(^|[^_A-Z=])\$\{?KEEP_DATABASE_URL`)
	for _, l := range strings.Split(doc, "\n") {
		if strings.Contains(l, "KEEP_DATABASE_URL") && !strings.Contains(l, "GOOSE_DBSTRING=") &&
			re.MatchString(l) && !strings.HasPrefix(strings.TrimSpace(l), "|") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// Red run for the check above: a filled assignment and a stray name are caught.
func TestEnvExampleCheckCatchesAValue(t *testing.T) {
	c := canary.New()
	if len(envExampleProblems("KEEP_DATABASE_URL="+c.Value(1))) == 0 {
		t.Fatal("a filled assignment was not detected")
	}
	if len(envExampleProblems("AWS_SECRET=")) == 0 {
		t.Fatal("an unknown name was not detected")
	}
	if len(envExampleProblems("# note\nKEEP_DATABASE_URL=\n")) != 0 {
		t.Fatal("a clean example was rejected")
	}
}

// A start that fails on a bad database must not print the URL (it carries a
// password) or the root key path content.
func TestFailedStartPrintsNoConfigValues(t *testing.T) {
	c := canary.New()
	t.Setenv("KEEP_DATABASE_URL", "postgres://keep:"+c.Value(1)+"@127.0.0.1:1/keep?connect_timeout=1")
	// The root key file's path is not a secret, its content is.
	keyFile := t.TempDir() + "/root.key"
	if err := os.WriteFile(keyFile, []byte(c.Value(2)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEEP_ROOT_KEY_FILE", keyFile)

	for _, args := range [][]string{{"keep-server"}, {"keep-server", "migrate", "status"}, {"keep-server", "migrate", "up"}} {
		out := capture(t, func() int { return app.Main(args, app.Options{}) })
		if out.code == 0 {
			t.Fatalf("%v: start against a dead database exited 0", args)
		}
		if c.In(out.text) {
			t.Fatalf("%v: output carries a configuration value", args)
		}
	}
}

type captured struct {
	code int
	text string
}

func capture(t *testing.T, fn func() int) captured {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := fn()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = w.Close()
	return captured{code: code, text: <-done}
}
