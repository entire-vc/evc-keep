package app

// keep-server issue-admin-token: the supported way to give an existing
// organization a fresh admin token when its last one expired. It creates
// nothing: the organization and its admin user must exist, the user must hold
// the admin role at the organization scope, and the token is issued for that
// user only. A refusal changes nothing.
//
// The journal record comes before the token exists. The token is shown once,
// in the file named by --token-file (mode 0600, never overwritten); stdout
// carries the org id, the token id, the expiry and the path, never the value.

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
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const issueAdminUsage = "usage: keep-server issue-admin-token --org-id <uuid> --admin-user-id <uuid> --ttl <duration, at most 720h> --token-file <absolute path>"

func runIssueAdminToken(ctx context.Context, args []string) int {
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
	return issueAdminToken(ctx, pool, slog.New(slog.NewJSONHandler(io.Discard, nil)), args, os.Stdout, os.Stderr)
}

// issueAdminTokenFail prints a refusal as class + template, like
// bootstrapFail.
// issueAppend writes a journal record; a test swaps it to reach the
// journal-failure path.
var issueAppend = func(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, r audit.Record) error {
	_, err := audit.NewJournal(pool).WithLogger(logger).Append(ctx, r)
	return err
}

func issueAdminTokenFail(stderr io.Writer, class apperr.Class, message string) int {
	_, _ = fmt.Fprintf(stderr, "issue-admin-token failed: error_class=%s: %s\n", class, message)
	return 1
}

func issueAdminToken(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("issue-admin-token", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	orgArg := fs.String("org-id", "", "")
	userArg := fs.String("admin-user-id", "", "")
	tokenFile := fs.String("token-file", "", "")
	ttlArg := fs.String("ttl", "", "")
	if err := fs.Parse(args); err != nil || *orgArg == "" || *userArg == "" || *tokenFile == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, issueAdminUsage)
		return 2
	}
	orgID, err := uuid.Parse(*orgArg)
	if err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInvalidArgument, "--org-id is not a uuid")
	}
	userID, err := uuid.Parse(*userArg)
	if err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInvalidArgument, "--admin-user-id is not a uuid")
	}
	ttl, err := time.ParseDuration(*ttlArg)
	if err != nil || ttl <= 0 || ttl > bootstrapMaxTTL {
		return issueAdminTokenFail(stderr, apperr.ClassInvalidArgument, "--ttl is required, positive and at most 720h")
	}
	if !filepath.IsAbs(*tokenFile) {
		return issueAdminTokenFail(stderr, apperr.ClassInvalidArgument, "--token-file must be an absolute path")
	}

	// The destination must be free and its directory writable before the
	// database is touched.
	dest := filepath.Clean(*tokenFile)
	if _, err := os.Lstat(dest); err == nil {
		return issueAdminTokenFail(stderr, apperr.ClassAlreadyExists, "token file already exists; it is never overwritten")
	}
	probe, err := os.CreateTemp(filepath.Dir(dest), ".keep-issue-*")
	if err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInvalidArgument, "token file directory is not writable")
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())

	var orgExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)`, orgID).Scan(&orgExists); err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot read the organization")
	}
	if !orgExists {
		return issueAdminTokenFail(stderr, apperr.ClassNotFound, "organization not found")
	}
	user, err := tenancy.New(pool).GetUser(ctx, orgID, userID)
	if errors.Is(err, tenancy.ErrNotFound) {
		return issueAdminTokenFail(stderr, apperr.ClassNotFound, "user not found in this organization")
	}
	if err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot read the user")
	}
	scope := tenancy.Org(orgID)
	ids := identity.NewRepo(pool)
	role, member, err := ids.UserRole(ctx, orgID, userID, scope.String())
	if err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot read the user's role")
	}
	if user.Status != "active" || !member || role != identity.RoleAdmin {
		return issueAdminTokenFail(stderr, apperr.ClassPermissionDenied, "user is not an active admin of the organization")
	}

	tokenID, err := uuid.NewV7()
	if err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot generate the token id")
	}
	expiresAt := time.Now().UTC().Add(ttl)
	// The journal record comes before the token exists: no record, no token.
	if err := issueAppend(ctx, pool, logger, audit.Record{
		OrgID:  orgID.String(),
		Scope:  scope.String(),
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "keep-server-issue-admin-token", Via: audit.ViaCLI},
		Intent: audit.Intent{Reason: audit.NewReason(fmt.Sprintf("admin_user_id=%s token_id=%s expires_at=%s", userID, tokenID, expiresAt.Format(time.RFC3339)))},
		Action: audit.ActionTokenIssue,
		Result: audit.Result{Status: audit.StatusOK},
	}); err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot write the audit record")
	}

	issued, err := ids.Issue(ctx, identity.IssueParams{
		OrgID: orgID, Kind: identity.KindUser, PrincipalID: userID, Scope: scope.String(), ExpiresAt: &expiresAt, TokenID: tokenID,
	})
	if err != nil {
		return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot issue the admin token")
	}
	if err := writeTokenFile(dest, issued.Token); err != nil {
		// A token nobody holds must not stay valid.
		if ids.Revoke(context.WithoutCancel(ctx), identity.Principal{OrgID: orgID}, issued.TokenID) != nil {
			return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot write the token file, and revoking the issued token failed")
		}
		// The journal said the token was issued; it must also say it was revoked.
		if err := issueAppend(context.WithoutCancel(ctx), pool, logger, audit.Record{
			OrgID:  orgID.String(),
			Scope:  scope.String(),
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "keep-server-issue-admin-token", Via: audit.ViaCLI},
			Intent: audit.Intent{Reason: audit.NewReason(fmt.Sprintf("token_id=%s undelivered", issued.TokenID))},
			Action: audit.ActionTokenRevoke,
			Result: audit.Result{Status: audit.StatusOK},
		}); err != nil {
			return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot write the token file; the issued token is revoked, but the revocation could not be journaled")
		}
		return issueAdminTokenFail(stderr, apperr.ClassInternal, "cannot write the token file; the issued token is revoked")
	}

	logger.InfoContext(ctx, "admin_token_issued", "org_id", orgID.String(), "token_id", issued.TokenID.String())
	_, _ = fmt.Fprintf(stdout, "org_id=%s\ntoken_id=%s\nexpires_at=%s\ntoken_file=%s\n", orgID, issued.TokenID, expiresAt.Format(time.RFC3339), dest)
	return 0
}
