package app

// keep-server bootstrap-org: the supported way to create the first
// organization of a fresh server and the admin token that POST /mesh/install
// and the token routes need. It goes through the application's own
// repositories (tenancy, orgpki, catalog, identity, audit), so the CA, the
// default store, the admin membership and the journal record are the ones an
// ordinary creation makes.
//
// The token is shown once, in the file named by --token-file (mode 0600,
// never overwritten). stdout carries the org id and the path; the token is
// in no stream, log line, error or journal record.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/jackc/pgx/v5/pgxpool"
)

const bootstrapUsage = "usage: keep-server bootstrap-org --name <name> --admin-email <email> --token-file <absolute path> --ttl <duration, at most 720h>"

type bootstrapDeps struct {
	pool   *pgxpool.Pool
	local  *builtin.Local
	logger *slog.Logger
}

func runBootstrapOrg(ctx context.Context, args []string) int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pool.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	local, err := builtin.OpenLocalFile(pool, cfg.RootKeyFile, cfg.RootKeyID, logger, func(builtin.KeyEvent) {})
	if err != nil {
		fmt.Fprintln(os.Stderr, "root key:", err)
		return 1
	}
	return bootstrapOrg(ctx, bootstrapDeps{pool: pool, local: local, logger: logger}, args, os.Stdout, os.Stderr)
}

// bootstrapMaxTTL bounds the admin token's lifetime: 30 days.
const bootstrapMaxTTL = 720 * time.Hour

// writeTokenFile is identity.WriteTokenFile; a test swaps it to reach the
// undelivered-token path.
var writeTokenFile = identity.WriteTokenFile

// bootstrapFail prints a refusal as class + template; never a foreign
// err.Error(), which could carry a path or a DSN fragment.
func bootstrapFail(stderr io.Writer, class apperr.Class, message string) int {
	_, _ = fmt.Fprintf(stderr, "bootstrap-org failed: error_class=%s: %s\n", class, message)
	return 1
}

func bootstrapOrg(ctx context.Context, d bootstrapDeps, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bootstrap-org", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "")
	email := fs.String("admin-email", "", "")
	tokenFile := fs.String("token-file", "", "")
	ttlArg := fs.String("ttl", "", "")
	if err := fs.Parse(args); err != nil || *name == "" || *email == "" || *tokenFile == "" {
		_, _ = fmt.Fprintln(stderr, bootstrapUsage)
		return 2
	}
	// Parsed here, not by the flag set, so that a malformed value is a
	// classified refusal like a missing or out-of-range one.
	ttl, err := time.ParseDuration(*ttlArg)
	if err != nil || ttl <= 0 || ttl > bootstrapMaxTTL {
		return bootstrapFail(stderr, apperr.ClassInvalidArgument, "--ttl is required, positive and at most 720h")
	}
	if !filepath.IsAbs(*tokenFile) {
		return bootstrapFail(stderr, apperr.ClassInvalidArgument, "--token-file must be an absolute path")
	}

	// Refuse before creating anything: the destination must be free and its
	// directory writable.
	dest := filepath.Clean(*tokenFile)
	if _, err := os.Lstat(dest); err == nil {
		return bootstrapFail(stderr, apperr.ClassAlreadyExists, "token file already exists; it is never overwritten")
	}
	probe, err := os.CreateTemp(filepath.Dir(dest), ".keep-bootstrap-*")
	if err != nil {
		return bootstrapFail(stderr, apperr.ClassInvalidArgument, "token file directory is not writable")
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())

	tn := tenancy.New(d.pool)
	org, err := tn.CreateOrganizationUniqueName(ctx, *name, "")
	if errors.Is(err, tenancy.ErrOrganizationNameTaken) {
		return bootstrapFail(stderr, apperr.ClassAlreadyExists, "an organization with this name already exists")
	}
	if err != nil {
		var ae *apperr.Error
		if errors.As(err, &ae) {
			return bootstrapFail(stderr, ae.Class, "invalid organization name")
		}
		return bootstrapFail(stderr, apperr.ClassInternal, "cannot create the organization")
	}
	// From here on an org exists; every refusal names it so the operator can
	// remove it (docs/bootstrap-org.md).
	fail := func(class apperr.Class, message string) int {
		_, _ = fmt.Fprintf(stderr, "org_id=%s left behind, see docs/bootstrap-org.md to remove it\n", org.ID)
		return bootstrapFail(stderr, class, message)
	}
	if _, err := orgpki.NewRepoFromLocal(d.pool, d.local).Ensure(ctx, org.ID); err != nil {
		return fail(apperr.ClassInternal, "cannot create the organization CA")
	}
	// Without a store bound at the org scope the first secret is refused
	// with no_store_bound.
	if _, _, err := catalog.New(d.pool).EnsureDefaultBuiltinStore(ctx, org.ID); err != nil {
		return fail(apperr.ClassInternal, "cannot create the default store")
	}
	user, err := tn.CreateUser(ctx, org.ID, *email)
	if err != nil {
		return fail(apperr.ClassInternal, "cannot create the admin user")
	}
	scope := tenancy.Org(org.ID)
	if _, err := tn.CreateMembership(ctx, org.ID, user.ID, scope, string(identity.RoleAdmin)); err != nil {
		return fail(apperr.ClassInternal, "cannot grant the admin role")
	}

	// The journal record comes before the token exists: no record, no token.
	journal := audit.NewJournal(d.pool).WithLogger(d.logger)
	if _, err := journal.Append(ctx, audit.Record{
		OrgID:  org.ID.String(),
		Scope:  scope.String(),
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "keep-server-bootstrap-org", Via: audit.ViaCLI},
		Action: audit.ActionOrgBootstrap,
		Result: audit.Result{Status: audit.StatusOK},
	}); err != nil {
		return fail(apperr.ClassInternal, "cannot write the audit record")
	}

	expiresAt := time.Now().UTC().Add(ttl)
	ids := identity.NewRepo(d.pool)
	issued, err := ids.Issue(ctx, identity.IssueParams{
		OrgID: org.ID, Kind: identity.KindUser, PrincipalID: user.ID, Scope: scope.String(), ExpiresAt: &expiresAt,
	})
	if err != nil {
		return fail(apperr.ClassInternal, "cannot issue the admin token")
	}
	if err := writeTokenFile(dest, issued.Token); err != nil {
		// A token nobody holds must not stay valid.
		if ids.Revoke(context.WithoutCancel(ctx), identity.Principal{OrgID: org.ID}, issued.TokenID) != nil {
			return fail(apperr.ClassInternal, "cannot write the token file, and revoking the issued token failed")
		}
		return fail(apperr.ClassInternal, "cannot write the token file; the issued token is revoked")
	}

	d.logger.InfoContext(ctx, "org_bootstrapped", "org_id", org.ID.String())
	_, _ = fmt.Fprintf(stdout, "org_id=%s\ntoken_file=%s\n", org.ID, dest)
	return 0
}
