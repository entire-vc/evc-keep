package app

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newInputService(pool *pgxpool.Pool, local *builtin.Local, origin string, log *slog.Logger) (*intake.Service, error) {
	if origin == "" {
		return nil, nil
	}
	invalid := errors.New("input links require KEEP_ROOT_KEY_FILE and a secure KEEP_PUBLIC_URL")
	u, err := url.Parse(origin)
	secure := u != nil && (u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))
	if !secure || local == nil || err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, invalid
	}
	factory := func(st catalog.Store) (intake.Receiver, error) {
		prov, err := builtinProvider(pool, local, st)
		if err != nil {
			return nil, intake.ErrUnavailable
		}
		return prov, nil
	}
	return intake.New(pool, factory, audit.NewJournal(pool), origin), nil
}

func expireInputLinks(ctx context.Context, svc *intake.Service, log *slog.Logger) {
	if svc == nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if svc.Expire(ctx) != nil {
				log.Error("input link expiration failed", "error_class", "intake_unavailable")
			}
		}
	}
}
