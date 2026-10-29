package app

// keep-server bind-default-store: binds the builtin store "default" at the
// organization scope of an organization created before bootstrap-org did it
// itself. The same call as in bootstrap-org (catalog.EnsureDefaultBuiltinStore),
// so running it on an organization that already has a binding changes
// nothing. stdout carries ids only: org_id, store_id and whether the binding
// was created or already there.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const bindDefaultStoreUsage = "usage: keep-server bind-default-store --org-id <uuid>"

func runBindDefaultStore(ctx context.Context, args []string) int {
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
	return bindDefaultStore(ctx, pool, slog.New(slog.NewJSONHandler(io.Discard, nil)), args, os.Stdout, os.Stderr)
}

// bindDefaultStoreFail prints a refusal as class + template, like
// bootstrapFail.
func bindDefaultStoreFail(stderr io.Writer, class apperr.Class, message string) int {
	_, _ = fmt.Fprintf(stderr, "bind-default-store failed: error_class=%s: %s\n", class, message)
	return 1
}

func bindDefaultStore(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bind-default-store", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	orgArg := fs.String("org-id", "", "")
	if err := fs.Parse(args); err != nil || *orgArg == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, bindDefaultStoreUsage)
		return 2
	}
	org, err := uuid.Parse(*orgArg)
	if err != nil {
		return bindDefaultStoreFail(stderr, apperr.ClassInvalidArgument, "--org-id is not a uuid")
	}

	storeID, created, err := catalog.New(pool).EnsureDefaultBuiltinStore(ctx, org)
	if err != nil {
		var ae *apperr.Error
		if errors.As(err, &ae) {
			return bindDefaultStoreFail(stderr, ae.Class, ae.Message)
		}
		return bindDefaultStoreFail(stderr, apperr.ClassInternal, "cannot bind the default store")
	}
	binding := "exists"
	if created {
		binding = "created"
	}
	scope := tenancy.Org(org)
	journal := audit.NewJournal(pool).WithLogger(logger)
	if _, err := journal.Append(ctx, audit.Record{
		OrgID:  org.String(),
		Scope:  scope.String(),
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "keep-server-bind-default-store", Via: audit.ViaCLI},
		Intent: audit.Intent{Reason: audit.NewReason(fmt.Sprintf("store_id=%s binding=%s", storeID, binding))},
		Action: audit.ActionStoreBindDefault,
		Result: audit.Result{Status: audit.StatusOK},
	}); err != nil {
		return bindDefaultStoreFail(stderr, apperr.ClassInternal, "cannot write the audit record")
	}

	logger.InfoContext(ctx, "default_store_bound", "org_id", org.String())
	_, _ = fmt.Fprintf(stdout, "org_id=%s store_id=%s binding=%s\n", org, storeID, binding)
	return 0
}
