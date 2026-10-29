package app

// keep-server set-deploy-policy: replaces an organization's deployment policy
// (the rules that let a deployment or an exec run without a person's
// approval) as a whole, from a JSON file on the server host. Every secret and
// runner a rule names must belong to the organization. The new revision and
// the journal record commit together; stdout carries counts and rule keys
// (ids, kinds, path prefixes), never a value.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const setDeployPolicyUsage = "usage: keep-server set-deploy-policy --org-id <uuid> --policy-file <path> [--max-deploys-per-hour N] [--expect-revision N] [--dry-run]"

// classConflict is this command's refusal for a stale --expect-revision. It
// is printed on the host only and is not an API error class.
const classConflict apperr.Class = "conflict"

// maxPolicyFile bounds the policy file: 256 rules of a few hundred bytes.
const maxPolicyFile = 1 << 20

func runSetDeployPolicy(ctx context.Context, args []string) int {
	return setDeployPolicyFromEnv(ctx, args, os.Stdout, os.Stderr)
}

// setDeployPolicyFromEnv opens the server's database. Configuration errors
// name variables only; a database that cannot be opened gets a fixed message,
// so the DSN never reaches the output.
func setDeployPolicyFromEnv(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := config.FromEnv()
	if err != nil {
		return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, err.Error())
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return setDeployPolicyFail(stderr, apperr.ClassNotReady, "cannot open the database")
	}
	defer pool.Close()
	return setDeployPolicy(ctx, pool, slog.New(slog.NewJSONHandler(io.Discard, nil)), args, stdout, stderr)
}

// setDeployPolicyFail prints a refusal as class + template, like
// bindDefaultStoreFail.
func setDeployPolicyFail(stderr io.Writer, class apperr.Class, message string) int {
	_, _ = fmt.Fprintf(stderr, "set-deploy-policy failed: error_class=%s: %s\n", class, message)
	return 1
}

func setDeployPolicy(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("set-deploy-policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	orgArg := fs.String("org-id", "", "")
	fileArg := fs.String("policy-file", "", "")
	maxPerHour := fs.Int("max-deploys-per-hour", 0, "")
	expect := fs.Int64("expect-revision", -1, "")
	dryRun := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args); err != nil || *orgArg == "" || *fileArg == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, setDeployPolicyUsage)
		return 2
	}
	org, err := uuid.Parse(*orgArg)
	if err != nil {
		return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, "--org-id is not a uuid")
	}
	maxSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "max-deploys-per-hour" {
			maxSet = true
		}
	})
	if maxSet && (*maxPerHour < 1 || *maxPerHour > 1000) {
		return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, "--max-deploys-per-hour must be 1..1000")
	}
	if *expect < -1 {
		return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, "--expect-revision must be 0 or more")
	}
	data, err := readPolicyFile(*fileArg)
	if err != nil {
		return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, err.Error())
	}
	p, err := deployment.DecodePolicy(data)
	if err != nil {
		return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, err.Error())
	}

	repo := deployment.NewRepo(pool, audit.NewJournal(pool).WithLogger(logger))
	res, err := repo.SetPolicy(ctx, deployment.PolicyChange{
		OrgID: org, Policy: p, MaxPerHour: *maxPerHour, ExpectRevision: *expect, DryRun: *dryRun,
		Actor: audit.Actor{Type: audit.ActorSystem, ID: "keep-server-set-deploy-policy", Via: audit.ViaCLI},
	})
	if err != nil {
		var pe *deployment.PolicyError
		switch {
		case errors.As(err, &pe):
			return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, pe.Error())
		case errors.Is(err, deployment.ErrRevisionMismatch):
			return setDeployPolicyFail(stderr, classConflict, "--expect-revision does not match the stored revision; nothing written")
		case errors.Is(err, deployment.ErrNotFound):
			return setDeployPolicyFail(stderr, apperr.ClassNotFound, "organization not found")
		case errors.Is(err, deployment.ErrInvalidArgument):
			return setDeployPolicyFail(stderr, apperr.ClassInvalidArgument, "invalid policy change")
		}
		return setDeployPolicyFail(stderr, apperr.ClassInternal, "cannot store the policy")
	}

	mode := ""
	if *dryRun {
		mode = " dry_run=true"
	} else {
		logger.InfoContext(ctx, "deploy_policy_set", "org_id", org.String())
	}
	_, _ = fmt.Fprintf(stdout, "org_id=%s revision=%d rules=%d exec_rules=%d max_deploys_per_hour=%d%s\n",
		org, res.Revision, res.Rules, res.ExecRules, res.MaxPerHour, mode)
	_, _ = fmt.Fprintf(stdout, "change: %s\n", deployment.PolicyChangeReason(res))
	return 0
}

// readPolicyFile reads at most maxPolicyFile bytes; a larger file is refused
// rather than cut.
func readPolicyFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the file on the host
	if err != nil {
		return nil, errors.New("cannot read --policy-file")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyFile+1))
	if err != nil {
		return nil, errors.New("cannot read --policy-file")
	}
	if len(data) > maxPolicyFile {
		return nil, errors.New("--policy-file is larger than 1 MiB")
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("--policy-file is empty")
	}
	return data, nil
}
