package app

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// buildKeepServer builds this package's own binary once per test run, so
// TestProcessNeverLeaksDSNOnFailure can exercise it the way an operator
// would: as a real process, not by calling runServe/runMigrate in-process.
func buildKeepServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keep-server")
	// bin is this test's own t.TempDir() path, never external input.
	cmd := exec.Command("go", "build", "-o", bin, "github.com/entire-vc/evc-keep/cmd/keep-server") //nolint:gosec // G204: bin is a fixed name under a test-owned temp dir, not external input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build keep-server: %v\n%s", err, out)
	}
	return bin
}

// Process-level counterpart to store.TestOpenNeverLeaksDSNOnFailure and
// store.TestOpenMigrationDBNeverLeaksDSNOnFailure. Those two prove the
// store package's own functions never return an unsanitized error; this
// test proves the actual thing that matters — that the
// *process*, run the way an operator runs it, never prints a canary from
// KEEP_DATABASE_URL on stdout or stderr, through any of its three
// entrypoints (bare, "migrate up", "migrate status").
//
// This covers a real gap: runServe and
// runMigrate both call store.OpenMigrationDB before store.Open is ever
// reached, and — before the fix that produced this test — that path's
// connection failure surfaced through goose's wrapped error text instead
// of through anything sanitized, so the process printed it raw on stderr
// even though store.Open itself was already safe.
func TestProcessNeverLeaksDSNOnFailure(t *testing.T) {
	bin := buildKeepServer(t)
	c := canary.New()
	canaryPW := c.Value(1)

	scenarios := []struct {
		name string
		// dsn builds the KEEP_DATABASE_URL for this scenario. It may skip
		// the calling subtest (not the whole test) if it needs something
		// the environment doesn't provide.
		dsn func(t *testing.T) string
	}{
		{
			name: "malformed dsn",
			dsn: func(t *testing.T) string {
				return "not a valid dsn with " + canaryPW + " inside ::: bad"
			},
		},
		{
			name: "unreachable port",
			dsn: func(t *testing.T) string {
				// 127.0.0.1:1 is a privileged, unlisted port — nothing
				// answers, so this fails fast with no server-issued
				// SQLSTATE at all. Same DSN shape store_test.go uses.
				return "postgres://postgres:" + canaryPW + "@127.0.0.1:1/keep?sslmode=disable"
			},
		},
		{
			name: "wrong password",
			dsn: func(t *testing.T) string {
				// This is the scenario that reproduces the fix's original
				// manual repro (a real SQLSTATE 28P01 from a reachable
				// server) — it needs a real, reachable Postgres, so it
				// reuses whatever KEEP_DATABASE_URL the test environment
				// already provides for the rest of this package's tests
				// (CI's postgres service; a local throwaway instance for
				// a developer running this by hand) and swaps in the
				// canary as the password, same convention as
				// store_test.go / migrate_test.go's test*DB helpers.
				base := os.Getenv("KEEP_DATABASE_URL")
				if base == "" {
					t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
				}
				u, err := url.Parse(base)
				if err != nil {
					t.Fatalf("parse KEEP_DATABASE_URL: %v", err)
				}
				u.User = url.UserPassword(u.User.Username(), canaryPW)
				return u.String()
			},
		},
	}

	invocations := []struct {
		name string
		args []string
	}{
		{"serve", nil},
		{"migrate up", []string{"migrate", "up"}},
		{"migrate status", []string{"migrate", "status"}},
	}

	for _, sc := range scenarios {
		for _, inv := range invocations {
			t.Run(sc.name+"/"+inv.name, func(t *testing.T) {
				dsn := sc.dsn(t)

				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()

				// bin is buildKeepServer's own output; inv.args comes only
				// from the hardcoded invocations slice above, never from
				// external input.
				cmd := exec.CommandContext(ctx, bin, inv.args...) //nolint:gosec // G204: both args are test-internal, not external input
				cmd.Env = append(os.Environ(),
					"KEEP_DATABASE_URL="+dsn,
					// Never reached in any of these scenarios (the schema
					// check fails first — see runServe's doc) but set to
					// something that can't collide with a real listener,
					// in case that ever changes.
					"KEEP_HTTP_ADDR=127.0.0.1:0",
				)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				runErr := cmd.Run()

				if ctx.Err() == context.DeadlineExceeded {
					t.Fatalf("keep-server did not exit within the timeout — stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				if runErr == nil {
					t.Fatalf("expected keep-server to exit non-zero against a %s DSN — stdout=%q stderr=%q", sc.name, stdout.String(), stderr.String())
				}

				if c.In(stdout.String()) {
					t.Errorf("canary leaked into process stdout: %q", stdout.String())
				}
				if c.In(stderr.String()) {
					t.Errorf("canary leaked into process stderr: %q", stderr.String())
				}
			})
		}
	}
}

// runServeAgainst runs the built binary's default (serve) entrypoint against
// dsn for at most d and returns its combined output, whether it was still
// running when d ran out, and its exit code (-1 if it did not exit on its
// own).
func runServeAgainst(t *testing.T, bin, dsn string, d time.Duration) (out string, stillRunning bool, code int) {
	t.Helper()
	return runServeWithRoot(t, bin, dsn, d, serverRootKeyFile(t), "local-v1")
}
func runServeWithRoot(t *testing.T, bin, dsn string, d time.Duration, rootFile, rootID string) (out string, stillRunning bool, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin) //nolint:gosec // G204: bin is buildKeepServer's own output
	cmd.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn, "KEEP_HTTP_ADDR=127.0.0.1:0", "KEEP_ROOT_KEY_FILE="+rootFile, "KEEP_ROOT_KEY_ID="+rootID, "KEEP_RUNNER_ADDR=127.0.0.1:0", "KEEP_DEV_EPHEMERAL_TLS=1")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run() // outcome read from ctx and ProcessState below
	if ctx.Err() == context.DeadlineExceeded {
		return buf.String(), true, -1
	}
	return buf.String(), false, cmd.ProcessState.ExitCode()
}

// migrate runs "keep-server migrate up" against dsn and fails the test if it
// does not succeed.
func migrate(t *testing.T, bin, dsn string) {
	t.Helper()
	cmd := exec.Command(bin, "migrate", "up") //nolint:gosec // G204: bin is buildKeepServer's own output
	cmd.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("migrate up: %v\n%s", err, out)
	}
}

// With PostgreSQL's default log settings, a rejected row is written in full
// to the server's own log. The server must refuse to start on such a
// database — before it listens — and start normally once both settings in
// store.RequiredLogSettings are in place (positive control: the refusal is
// about those settings, not about the scratch database).
func TestServeRefusesVerbosePostgresLog(t *testing.T) {
	bin := buildKeepServer(t)

	t.Run("server defaults", func(t *testing.T) {
		dsn := pgscratch.New(t, nil)
		migrate(t, bin, dsn)
		out, running, code := runServeAgainst(t, bin, dsn, 15*time.Second)
		if running {
			t.Fatalf("keep-server kept running on a database with default log settings: %q", out)
		}
		// A supervisor reads exit 0 as a clean stop and would not alert.
		if code != 1 {
			t.Fatalf("keep-server refused with exit code %d, want 1: %q", code, out)
		}
		if !strings.Contains(out, "refusing to start") || !strings.Contains(out, "log_error_verbosity") || !strings.Contains(out, "log_min_error_statement") {
			t.Fatalf("keep-server exited without naming both log settings: %q", out)
		}
		if strings.Contains(out, "listening") {
			t.Fatalf("keep-server opened a listener before refusing: %q", out)
		}
	})

	t.Run("required settings", func(t *testing.T) {
		// Literal, not store.RequiredLogSettings: a change to the required
		// values must fail here too.
		dsn := pgscratch.New(t, requiredLogSettingsLiteral)
		migrate(t, bin, dsn)
		// pgscratch.New's admin connection is a superuser in CI (see
		// pgscratch's doc) — serving as it would trip CheckNotSuperuser,
		// so this positive control needs the non-superuser role too.
		roleDSN := pgscratch.NewRole(t, dsn)
		out, running, _ := runServeAgainst(t, bin, roleDSN, 3*time.Second)
		if !running || !strings.Contains(out, "listening") {
			t.Fatalf("keep-server did not start on a correctly configured database: running=%v output=%q", running, out)
		}
	})
}

// requiredLogSettingsLiteral is the process-level tests' own literal copy of
// store.RequiredLogSettings plus log_statement — literal, not the package
// value, so a change to what's required still has to be reflected here to
// pass.
var requiredLogSettingsLiteral = map[string]string{
	"log_error_verbosity":         "terse",
	"log_min_error_statement":     "panic",
	"log_statement":               "'none'",
	"log_min_duration_statement":  "-1",
	"log_min_duration_sample":     "-1",
	"log_transaction_sample_rate": "0",
	"log_min_messages":            "fatal",
}

// Process-level counterpart to store.TestOpenRefusesUnsafeQueryExecMode /
// store.TestOpenMigrationDBRefusesUnsafeQueryExecMode: the server must
// refuse to start — before opening a listener — against a DSN that would
// have pgx write parameter values into the statement text or bind message
// it sends, regardless of how correctly RequiredLogSettings is set.
//
// This check runs inside store.OpenMigrationDB, ahead of even the schema
// check, and runServe reports that failure with fmt.Fprintln(os.Stderr,
// err) directly — unlike the two store.CheckLogSettings/CheckNotSuperuser
// refusals below, its output carries no "refusing to start" prefix.
func TestServeRefusesUnsafeQueryExecMode(t *testing.T) {
	bin := buildKeepServer(t)
	c := canary.New()
	pw := c.Value(1)
	for _, mode := range []string{"simple_protocol", "exec"} {
		t.Run(mode, func(t *testing.T) {
			dsn := "postgres://postgres:" + pw + "@127.0.0.1:1/keep?sslmode=disable&default_query_exec_mode=" + mode
			out, running, code := runServeAgainst(t, bin, dsn, 15*time.Second)
			if running {
				t.Fatalf("keep-server kept running against default_query_exec_mode=%s: %q", mode, out)
			}
			if code != 1 {
				t.Fatalf("keep-server refused with exit code %d, want 1: %q", code, out)
			}
			if !strings.Contains(out, mode) {
				t.Fatalf("keep-server exited without naming the exec-mode refusal: %q", out)
			}
			if strings.Contains(out, "listening") {
				t.Fatalf("keep-server opened a listener before refusing: %q", out)
			}
			if c.In(out) {
				t.Errorf("canary leaked into process output: %q", out)
			}
		})
	}
}

// A role with PostgreSQL superuser rights can undo everything
// CheckLogSettings verified with a plain SET, so the server must refuse to
// start under one even when every log setting is correctly configured —
// store.TestCheckNotSuperuser is the store-level counterpart; this is the
// same positive control as TestServeRefusesVerbosePostgresLog's "required
// settings" subtest, run as the superuser instead of the scratch role.
func TestServeRefusesSuperuserRole(t *testing.T) {
	bin := buildKeepServer(t)
	dsn := pgscratch.New(t, requiredLogSettingsLiteral)
	migrate(t, bin, dsn)

	out, running, code := runServeAgainst(t, bin, dsn, 15*time.Second)
	if running {
		t.Fatalf("keep-server kept running as a superuser role: %q", out)
	}
	if code != 1 {
		t.Fatalf("keep-server refused with exit code %d, want 1: %q", code, out)
	}
	if !strings.Contains(out, "refusing to start") || !strings.Contains(out, "superuser") {
		t.Fatalf("keep-server exited without naming the superuser refusal: %q", out)
	}
	if strings.Contains(out, "listening") {
		t.Fatalf("keep-server opened a listener before refusing: %q", out)
	}
}

func TestNewHTTPServerRoutesErrorLogThroughObs(t *testing.T) {
	var buf bytes.Buffer
	srv := newHTTPServer(":0", http.NotFoundHandler(), obs.New(&buf))
	if srv.ErrorLog == nil {
		t.Fatal("ErrorLog unset: net/http would log to the global stderr logger")
	}
	srv.ErrorLog.Printf("http: TLS handshake error from 203.0.113.9:1: CANARY")
	if out := buf.String(); !strings.Contains(out, `"error_class":"tls_handshake"`) || strings.Contains(out, "CANARY") {
		t.Fatalf("not routed through obs: %q", out)
	}
}

// TestEveryHTTPServerIsBuiltByNewHTTPServer is the guard behind "no Keep
// listener logs outside internal/obs": a bare http.Server literal in
// non-test code (runServe, a future runner mTLS listener) would leave
// ErrorLog nil. Only newHTTPServer may build one.
func TestEveryHTTPServerIsBuiltByNewHTTPServer(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var bad []string
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); path != root && (strings.HasPrefix(n, ".") || n == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		scanned++
		httpName := "http" // local name of net/http in this file
		for _, imp := range f.Imports {
			if imp.Path.Value == `"net/http"` && imp.Name != nil {
				httpName = imp.Name.Name
			}
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			allowed := fn != nil && fn.Name.Name == "newHTTPServer" &&
				filepath.ToSlash(path) == "../../../cmd/keep-server/app/main.go"
			ast.Inspect(decl, func(n ast.Node) bool {
				var typ ast.Expr
				switch x := n.(type) {
				case *ast.CompositeLit: // http.Server{...}
					typ = x.Type
				case *ast.ValueSpec: // var s http.Server
					typ = x.Type
				case *ast.TypeSpec: // type srv = http.Server
					typ = x.Type
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 { // new(http.Server)
						typ = x.Args[0]
					}
					// http.ListenAndServe and friends build a Server with a nil ErrorLog.
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && !allowed {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == httpName {
							switch sel.Sel.Name {
							case "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS":
								bad = append(bad, path)
							}
						}
					}
				}
				if sel, ok := typ.(*ast.SelectorExpr); ok && sel.Sel.Name == "Server" {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == httpName && !allowed {
						bad = append(bad, path)
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d files — the walk is broken, the guard proves nothing", scanned)
	}
	if len(bad) > 0 {
		t.Errorf("http.Server built outside newHTTPServer (ErrorLog would be nil): %v", bad)
	}
}
