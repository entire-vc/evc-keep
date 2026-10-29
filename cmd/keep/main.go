// Command keep is the Keep CLI: a thin HTTP client for Keep Server. It never
// imports pkg/secret (.golangci.yml's secret-value depguard rule denies that
// import from cmd/keep) and has no "show value" command — ADR-001 §3.4.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/entire-vc/evc-keep/internal/version"
)

const usage = `keep — Keep CLI

Usage:
  keep login [--token-file path]          reads the token from stdin
  keep login <token>                       deprecated: visible via ps/shell history
  keep list --scope-level LEVEL --scope-id ID [--json]
  keep meta <name> --scope-level LEVEL --scope-id ID [--json]
  keep version <name> --scope-level LEVEL --scope-id ID [--json]
  keep create-ref <name> --scope-level LEVEL --scope-id ID --class CLASS --type TYPE --provider-ref REF [--description TEXT] [--json]
  (LEVEL is one of: user, proj, ws, org)
  keep input-link <secret> [--ttl 30m] [--workspace ID] [--project ID]
  keep deploy <secret> --runner ID --target PATH --uid N --gid N [--kind env-file] [--field NAME] [--unit U] [--consumer C] [--mode 0600] [--request-id ID] [--wait 1m] [--json]
                                           exit 3: approval required, 4: result still pending
  keep mcp [--server URL] [--org ID] [--token-file PATH]
                                           serves MCP tools on stdin/stdout: list_secrets, get_secret_meta,
                                           request_secret_input, deploy; no tool takes or returns a value
  keep audit verify [--json]               checks the organization's audit chain; exit 1 if it is broken
  keep runner enroll-token --host HOST --policy FILE [--uid-shared=true|false] [--environment LABEL] [--platform LABEL]
  keep runner revoke RUNNER_ID
  keep -h | --help
  keep -V | --version

Global flags (list, meta, version, create-ref, audit verify):
  --server URL       Keep server base URL (or KEEP_SERVER)
  --org ID           organization id (or KEEP_ORG)
  --token-file PATH  token file to read when KEEP_TOKEN is unset (default: $XDG_CONFIG_HOME/keep/token or $HOME/.config/keep/token)
  --json             output as JSON instead of a table
  --debug            print redacted request/response traces to stderr

A secret's value is never available through this CLI — there is no command
that returns it, by design.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	case "-V", "--version":
		_, _ = fmt.Fprintln(stdout, version.String())
		return 0
	case "input-link":
		return runInputLink(rest, stdout, stderr, getenv)
	case "deploy":
		return runDeploy(rest, stdout, stderr, getenv)
	case "login":
		return runLoginSubcommand(rest, stdin, stderr, getenv)
	case "list":
		return runListSubcommand(rest, stdout, stderr, getenv)
	case "meta":
		return runMetaSubcommand(rest, stdout, stderr, getenv)
	case "version":
		return runVersionSubcommand(rest, stdout, stderr, getenv)
	case "create-ref":
		return runCreateRefSubcommand(rest, stdout, stderr, getenv)
	case "mcp":
		return runMCP(rest, stdin, stdout, stderr, getenv)
	case "runner":
		return runRunner(rest)
	case "audit":
		return runAuditSubcommand(rest, stdout, stderr, getenv)
	default:
		_, _ = fmt.Fprint(stderr, "keep: unknown command\n\n")
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
}

// globalOpts holds the flags shared by every command that talks to a server.
type globalOpts struct {
	server    string
	org       string
	tokenFile string
	jsonOut   bool
	debug     bool
}

func bindGlobalFlags(fs *flag.FlagSet, getenv func(string) string) *globalOpts {
	o := &globalOpts{}
	// No KEEP_SERVER default here: flag prints defaults on -h and on parse errors,
	// and the URL may carry a userinfo password. newClient falls back instead.
	fs.StringVar(&o.server, "server", "", "Keep server base URL (default $KEEP_SERVER)")
	fs.StringVar(&o.org, "org", getenv("KEEP_ORG"), "organization id")
	fs.StringVar(&o.tokenFile, "token-file", defaultTokenPath(getenv), "path to the token file (used when KEEP_TOKEN is unset)")
	fs.BoolVar(&o.jsonOut, "json", false, "output as JSON instead of a table")
	fs.BoolVar(&o.debug, "debug", false, "print redacted request/response traces to stderr")
	return o
}

func (o *globalOpts) newClient(getenv func(string) string, stderr io.Writer) (*client, error) {
	server := o.server
	if server == "" {
		server = getenv("KEEP_SERVER")
	}
	if server == "" {
		return nil, errors.New("--server or KEEP_SERVER is required")
	}
	if o.org == "" {
		return nil, errors.New("--org or KEEP_ORG is required")
	}
	su, err := url.Parse(server)
	if err != nil {
		// Not wrapped: url.Error's own Error() text repeats the raw --server
		// value, which can carry a userinfo password (http://user:pass@host).
		return nil, errors.New("--server: invalid URL")
	}
	if err := requireSecureURL(su); err != nil {
		return nil, fmt.Errorf("--server: %w", err)
	}
	tok, err := resolveToken(getenv, o.tokenFile)
	if err != nil {
		return nil, err
	}
	return newClient(server, o.org, tok, o.debug, stderr), nil
}

func bindScopeFlags(fs *flag.FlagSet) (level, id *string) {
	level = fs.String("scope-level", "", "scope level: user|proj|ws|org")
	id = fs.String("scope-id", "", "scope id")
	return level, id
}

var errMissingPositional = errors.New("a positional argument is required")

// splitPositional consumes args[0] as a positional argument before any flag
// parsing happens. The flag package stops recognizing flags at the first
// non-flag token, so a subcommand taking both a positional name and flags
// (e.g. `keep meta my-secret --scope-level user --scope-id ...`) must pull
// the name out first and hand fs.Parse only what follows it.
func splitPositional(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, errMissingPositional
	}
	return args[0], args[1:], nil
}

// runLoginSubcommand prefers stdin for the token: a token given as a
// positional argument is visible to every other local user via `ps` (and on
// Linux, /proc/<pid>/cmdline) for as long as the process runs, and lands in
// shell history the moment the command is typed — the positional form stays
// only for backward compatibility and warns on every use.
func runLoginSubcommand(args []string, stdin io.Reader, stderr io.Writer, getenv func(string) string) int {
	token, rest, posErr := splitPositional(args)
	fromStdin := posErr != nil
	if fromStdin {
		rest = args
	}
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	// A token that starts with "-" is parsed as an unknown flag, and the
	// stdlib's own parse error ("flag provided but not defined: -TOKEN")
	// embeds it verbatim on the FlagSet's output — so that output is
	// discarded and only our own message, naming no argument value, is shown.
	fs.SetOutput(io.Discard)
	tokenFile := fs.String("token-file", defaultTokenPath(getenv), "path to write the token file")
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(stderr, usage)
			return 0
		}
		// The flag package's "provided but not defined" error is how a
		// token starting with "-" surfaces. Only the fact is reported:
		// err's text carries the argument and is never printed.
		if strings.HasPrefix(err.Error(), "flag provided but not defined") {
			_, _ = fmt.Fprintln(stderr, `keep login: an argument starting with "-" is not a known flag; if it is the token, pipe it on stdin instead: `+"`keep login < token-file`")
			return 2
		}
		_, _ = fmt.Fprintln(stderr, "keep login: could not parse arguments — usage: `keep login [--token-file PATH] < token-file`")
		return 2
	}
	// flag.FlagSet.Parse stops at the first non-flag argument, so a token
	// placed after a flag (`keep login --token-file P TOKEN`) is never
	// consumed above — it lands here instead of being silently dropped and
	// falling through to the stdin path with no warning at all.
	if extra := fs.Args(); len(extra) > 0 {
		// %v on extra would print the leftover argument itself — for
		// `keep login --token-file P TOKEN` that argument IS the token, so
		// only its count is safe to put in an error message.
		_, _ = fmt.Fprintf(stderr, "keep login: %d unexpected argument(s) after flags — pipe the token on stdin instead: `keep login --token-file PATH < token-file`\n", len(extra))
		return 2
	}
	if *tokenFile == "" {
		_, _ = fmt.Fprintln(stderr, "keep login: --token-file could not be determined (set HOME or pass --token-file explicitly)")
		return 2
	}
	if fromStdin {
		b, err := io.ReadAll(stdin)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "keep login: read token from stdin: %v\n", err)
			return 2
		}
		token = string(b)
	} else {
		_, _ = fmt.Fprintln(stderr, "keep login: passing the token as an argument is visible to other local users via `ps` and is kept in shell history — pipe it on stdin instead, e.g. `keep login < token-file`")
	}
	if err := runLogin(*tokenFile, token); err != nil {
		return reportErr(stderr, err)
	}
	_, _ = fmt.Fprintln(stderr, "keep: token written")
	return 0
}

func runListSubcommand(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	scopeLevel, scopeID := bindScopeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return flagParseFailed(fs.Name(), err, stderr)
	}
	if *scopeLevel == "" || *scopeID == "" {
		_, _ = fmt.Fprintln(stderr, "keep list: --scope-level and --scope-id are required")
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	if err := cmdList(c, *scopeLevel, *scopeID, g.jsonOut, stdout); err != nil {
		return reportErr(stderr, err)
	}
	return 0
}

func runMetaSubcommand(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	name, rest, err := splitPositional(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keep meta: a secret name is required")
		return 2
	}
	fs := flag.NewFlagSet("meta", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	scopeLevel, scopeID := bindScopeFlags(fs)
	if err := fs.Parse(rest); err != nil {
		return flagParseFailed(fs.Name(), err, stderr)
	}
	if *scopeLevel == "" || *scopeID == "" {
		_, _ = fmt.Fprintln(stderr, "keep meta: --scope-level and --scope-id are required")
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	if err := cmdMeta(c, *scopeLevel, *scopeID, name, g.jsonOut, stdout); err != nil {
		return reportErr(stderr, err)
	}
	return 0
}

func runVersionSubcommand(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	name, rest, err := splitPositional(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keep version: a secret name is required")
		return 2
	}
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	scopeLevel, scopeID := bindScopeFlags(fs)
	if err := fs.Parse(rest); err != nil {
		return flagParseFailed(fs.Name(), err, stderr)
	}
	if *scopeLevel == "" || *scopeID == "" {
		_, _ = fmt.Fprintln(stderr, "keep version: --scope-level and --scope-id are required")
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	if err := cmdVersion(c, *scopeLevel, *scopeID, name, g.jsonOut, stdout); err != nil {
		return reportErr(stderr, err)
	}
	return 0
}

func runCreateRefSubcommand(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	name, rest, err := splitPositional(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keep create-ref: a secret name is required")
		return 2
	}
	fs := flag.NewFlagSet("create-ref", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	scopeLevel, scopeID := bindScopeFlags(fs)
	class := fs.String("class", "", "secret class")
	typ := fs.String("type", "", "secret type")
	providerRef := fs.String("provider-ref", "", "provider-side reference for the value")
	description := fs.String("description", "", "optional human-readable description")
	if err := fs.Parse(rest); err != nil {
		return flagParseFailed(fs.Name(), err, stderr)
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	in := createRefInput{
		ScopeLevel:  *scopeLevel,
		ScopeID:     *scopeID,
		Name:        name,
		Class:       *class,
		Type:        *typ,
		ProviderRef: *providerRef,
		Description: *description,
	}
	if err := cmdCreateRef(c, in, g.jsonOut, stdout); err != nil {
		return reportErr(stderr, err)
	}
	return 0
}

// runAuditSubcommand dispatches "keep audit <sub>"; only "verify" exists.
func runAuditSubcommand(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[0] != "verify" {
		_, _ = fmt.Fprintln(stderr, `keep audit: only "verify" is supported`)
		return 2
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	if err := fs.Parse(args[1:]); err != nil {
		return flagParseFailed(fs.Name(), err, stderr)
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "keep audit verify: %d unexpected argument(s)\n", fs.NArg())
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	ok, err := cmdAuditVerify(c, g.jsonOut, stdout)
	if err != nil {
		return reportErr(stderr, err)
	}
	if !ok {
		// A broken chain is a result, printed above, but a script gating on
		// the exit code must see it as a failure.
		return 1
	}
	return 0
}

// reportErr prints a client error or the server's closed error fields and
// returns the process exit code. Filesystem details are removed before any
// formatting because a credential may have been pasted into a path flag.
func reportErr(stderr io.Writer, err error) int {
	// A credential can be pasted into a path flag. Filesystem errors carry
	// that path (Rename carries both paths), so discard the original error
	// before formatting it. Never print its operation, path or cause.
	var pathErr *os.PathError
	var linkErr *os.LinkError
	if errors.As(err, &pathErr) || errors.As(err, &linkErr) {
		err = errors.New("file_error: filesystem operation failed")
	}
	var ae *apiError
	if errors.As(err, &ae) {
		_, _ = fmt.Fprintf(stderr, "keep: %s: %s\n", safeClass(ae.ErrorClass), sanitizeText(ae.Message, maxErrTextRunes))
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "keep: %s\n", err)
	return 1
}

func runRunner(args []string) int {
	if len(args) == 0 {
		runnerUsage()
		return 2
	}
	switch args[0] {
	case "enroll-token":
		return runRunnerEnrollToken(args[1:])
	case "revoke":
		return runRunnerRevoke(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "keep runner: unknown command")
		runnerUsage()
		return 2
	}
}

func runnerUsage() {
	fmt.Fprintln(os.Stderr, "Commands:\n  runner enroll-token -host <host> -policy <file> [-ttl <duration>]\n  runner revoke <runner_id>")
}

// flagParseFailed reports a flag.Parse error without ever printing it: the
// stdlib text embeds the offending argument ("flag provided but not defined:
// -TOKEN", `invalid value "TOKEN" for flag`), and an argument is exactly where
// a pasted credential lands. Every FlagSet must use io.Discard as its output.
func flagParseFailed(name string, err error, stderr io.Writer) int {
	if errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprint(stderr, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "keep %s: could not parse arguments (an argument or flag value is not valid); run `keep %s -h`\n", name, name)
	return 2
}
