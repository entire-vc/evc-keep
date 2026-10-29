package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// wireMeshGate builds the Mesh confirmation service and, when the gate is
// configured, connects it: every new approval gets a card before it commits,
// and a timer cancels the cards of requests that lapsed (until ctx ends). It
// returns nil unless KEEP_MESH_EXTENSION=1. Without the gate configuration the
// service only receives answers; Open and Sweep refuse and Keep's core runs as
// it does without Mesh.
//
// With KEEP_MESH_WORKSPACE_ID the plugin gets a source of the actor token
// sealed in vault at that workspace's install; with KEEP_MESH_TOKEN_FILE it
// gets none and reads its file.
func wireMeshGate(ctx context.Context, cfg config.Config, opts Options, pool *pgxpool.Pool, vault gateVault, dep *deployment.Repo, rot api.RotationService, logger *slog.Logger) (*meshgate.Service, error) {
	if !cfg.MeshExtension {
		return nil, nil
	}
	var cards gatecard.Cards
	if cfg.MeshGate.Enabled {
		if opts.Cards == nil {
			return nil, errors.New("the Mesh gate is configured (KEEP_MESH_PROJECT_ID) but this build has no Mesh plugin")
		}
		tokens, err := gateTokens(cfg.MeshGate, pool, vault)
		if err != nil {
			return nil, err
		}
		from := "a file"
		if tokens != nil {
			from = "the vault"
		}
		c, err := opts.Cards(cfg.MeshGate, tokens, logger)
		if err != nil || c == nil {
			// The plugin's own text is not printed: it is not Keep's to vouch for.
			return nil, errors.New("the Mesh gate configuration was refused by the Mesh plugin")
		}
		cards = c
		if logger != nil {
			logger.Info("mesh gate on: actor token from " + from)
		}
	}
	gates := meshgate.New(meshgate.NewPG(pool), deployment.GateApprovals{Src: gateSource{dep: dep, rot: rot}}, cards, logger).
		WithApprovers(gateApprovers{ir: identity.NewRepo(pool)})
	if cards == nil {
		return gates, nil
	}
	conf := deployment.GateConfirmer{Svc: gates}
	dep.WithConfirmer(conf)
	svc, ok := rot.(*rotation.Service)
	if rot != nil && !ok {
		// The concrete type, as in rotationResumeSweep: a changed type must stop
		// the start instead of leaving prod rotations without a card.
		return nil, errors.New("the rotation service cannot ask for a Mesh card")
	}
	if ok {
		svc.WithConfirmer(conf)
	}
	every := cfg.MeshGate.SweepEvery
	if opts.SweepEvery > 0 {
		every = opts.SweepEvery
	}
	go runMeshSweep(ctx, gates, every, logger)
	return gates, nil
}

// gateTokens is the gate's source of the sealed actor token: nil when the gate
// reads KEEP_MESH_TOKEN_FILE instead.
func gateTokens(gate config.MeshGate, pool *pgxpool.Pool, vault gateVault) (GateTokenSource, error) {
	if gate.WorkspaceID == "" {
		return nil, nil
	}
	ws, err := uuid.Parse(gate.WorkspaceID)
	if err != nil || vault == nil {
		return nil, errors.New("the Mesh gate (KEEP_MESH_WORKSPACE_ID) cannot reach the sealed actor token")
	}
	return vaultGateToken{installs: meshext.NewRepo(pool), vault: vault, workspace: ws, meshURL: gate.URL}, nil
}

// gateApprovers is the role check of a Mesh gate answer: the console's, a
// user's approve permission in the secret's scope.
type gateApprovers struct{ ir *identity.Repo }

func (g gateApprovers) CanApprove(ctx context.Context, org, user uuid.UUID, scope tenancy.Scope) (bool, error) {
	perms, err := catalog.PermissionsAt(ctx, g.ir, tenancy.Context{Org: org, Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: user}}, scope)
	if err != nil {
		return false, err
	}
	return perms[identity.PermApprove], nil
}

// sweeper is the part of meshgate.Service the timer drives.
type sweeper interface {
	Sweep(ctx context.Context) (int, error)
}

// runMeshSweep cancels the cards of lapsed requests at once and then every
// interval until ctx ends. A Mesh failure is logged by class and the next
// tick tries again: the loop never stops on an error.
func runMeshSweep(ctx context.Context, s sweeper, every time.Duration, logger *slog.Logger) {
	sweep := func() {
		n, err := s.Sweep(ctx)
		switch {
		case err != nil:
			logger.Warn("mesh gate sweep failed", "error_class", "unavailable")
		case n > 0:
			logger.Info(fmt.Sprintf("mesh gate sweep cancelled %d card(s)", n))
		}
	}
	sweep()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
