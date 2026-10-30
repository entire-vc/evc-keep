package app

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// GateTokenSource is what a plugin gets of the Mesh actor token when the gate
// names its installation (KEEP_MESH_WORKSPACE_ID): the token Mesh handed over
// at install, sealed in Keep's vault. Token unseals it anew on every call, so a
// rotation or a new install is used by the next card without a restart. The
// caller must not keep, log or format the text.
type GateTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// ErrGateToken is every failure of the vault source: no extension installation
// of the workspace, its record or vault unavailable, a KEEP_MESH_URL that is not the
// Mesh the workspace was installed from, or no token sealed. It names
// neither the workspace nor the vault path, and carries no text of the cause.
var ErrGateToken = errors.New("mesh gate token unavailable")

// installations is the installation record: which organisation a workspace is
// connected to as an extension, and the Mesh address recorded at install. A
// store-only installation has no actor token to hand out. *meshext.Repo is the
// implementation.
type installations interface {
	ExtensionInstallation(ctx context.Context, workspace uuid.UUID) (org uuid.UUID, meshURL string, found bool, err error)
}

// gateVault is the sealed side. *builtin.MeshVault is the implementation.
type gateVault interface {
	ExtensionToken(ctx context.Context, org, workspace string) (string, error)
}

// vaultGateToken reads the actor token of one installation. The organisation
// comes from the installation record on each call, never from configuration,
// and the token is handed out only for meshURL (KEEP_MESH_URL, where the
// plugin sends it) of the same origin as the Mesh recorded at install: the
// token Mesh gave Keep never goes to another host because of one variable.
type vaultGateToken struct {
	installs  installations
	vault     gateVault
	workspace uuid.UUID
	meshURL   string
}

var _ GateTokenSource = vaultGateToken{}

// Token implements GateTokenSource.
func (s vaultGateToken) Token(ctx context.Context) (string, error) {
	org, installedFrom, ok, err := s.installs.ExtensionInstallation(ctx, s.workspace)
	if err != nil || !ok {
		return "", ErrGateToken
	}
	if !sameOrigin(s.meshURL, installedFrom) {
		return "", ErrGateToken
	}
	tok, err := s.vault.ExtensionToken(ctx, org.String(), s.workspace.String())
	if err != nil || tok == "" {
		return "", ErrGateToken
	}
	return tok, nil
}

// sameOrigin reports whether a and b are absolute URLs with the same scheme
// and host (port included), compared without regard to case.
func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil || ua.Host == "" {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}
