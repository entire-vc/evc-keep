package builtin

import (
	"crypto/rand"
	"errors"
	"strconv"
	"strings"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	kstore "github.com/entire-vc/evc-keep/internal/store"
)

// ErrTransferRewrap carries no key, record identifier or backend text.
var ErrTransferRewrap = errors.New("builtin: offline transfer rewrap failed")

// MaxTransferKEKs bounds one organisation's KEK closure.
const MaxTransferKEKs = 4096

// rewrapKEKsForTransfer rewraps a selected organisation's whole KEK closure
// from the source root to an independent target root. It is all-or-nothing:
// any refusal returns no records, so the caller never sees a partial set.
// KEK ID, organisation and domain are preserved (envelopes and their AAD stay
// valid); only the wrapping changes. Every record must belong to org, appear
// once, and be wrapped by source. Source and target must be independent
// roots: a target that opens a source wrapping is the same key material and
// is refused. Only temporary KEK bytes are unwrapped inside the sealer; no
// secret value is opened.
func rewrapKEKsForTransfer(org string, recs []sealer.KEKRecord, source, target sealer.RootKey) ([]sealer.KEKRecord, error) {
	if org == "" || len(recs) == 0 || len(recs) > MaxTransferKEKs || source == nil || target == nil {
		return nil, ErrTransferRewrap
	}
	if sameRoot(source, target) {
		return nil, ErrTransferRewrap
	}
	seen := make(map[string]struct{}, len(recs))
	out := make([]sealer.KEKRecord, 0, len(recs))
	for _, rec := range recs {
		if _, dup := seen[rec.ID]; dup {
			return nil, ErrTransferRewrap
		}
		seen[rec.ID] = struct{}{}
		moved, err := sealer.RewrapKEK(org, rec, source, target)
		if err != nil {
			return nil, ErrTransferRewrap
		}
		out = append(out, moved)
	}
	return out, nil
}

// sameRoot reports whether target can open what source wraps. A probe key is
// wrapped by source and offered to target; authentication, not an ID
// comparison, decides. Probe bytes are random and never leave this function.
func sameRoot(source, target sealer.RootKey) bool {
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return true // cannot prove independence: refuse
	}
	defer clear(probe)
	wrapped, err := source.Wrap(probe, []byte(rootIndependenceAAD))
	if err != nil {
		return true
	}
	return opensProbe(target, wrapped)
}

// rootIndependenceAAD binds the independence probe to its one purpose.
const rootIndependenceAAD = "keep/offline-transfer/root-independence/v1"

// opensProbe reports whether root authenticates a probe wrapped by another
// root: only the same key material does.
func opensProbe(root sealer.RootKey, wrapped []byte) bool {
	plain, err := root.Unwrap(wrapped, []byte(rootIndependenceAAD))
	clear(plain)
	return err == nil
}

// kekScope rebuilds the KEK domain from a stored row and requires the stored
// domain_key to be exactly what the sealer would have rendered for it: the
// sealer binds the rendered key into the KEK AAD, so a row whose columns and
// key disagree must not travel.
func kekScope(r kstore.KEKRow) (sealer.Scope, bool) {
	sc := sealer.Scope{
		PKI: strings.HasPrefix(r.DomainKey, "pki:"), Org: r.DomainOrg,
		Workspace: r.DomainWorkspace, Project: r.DomainProject, User: r.DomainUser,
	}
	lp := func(id string) string { return strconv.Itoa(len(id)) + ":" + id }
	var want string
	switch {
	case sc.PKI:
		want = "pki:" + lp(sc.Org)
	case sc.User != "":
		want = "org:" + lp(sc.Org) + "/user:" + lp(sc.User)
	case sc.Project != "":
		want = "org:" + lp(sc.Org) + "/ws:" + lp(sc.Workspace) + "/proj:" + lp(sc.Project)
	case sc.Workspace != "":
		want = "org:" + lp(sc.Org) + "/ws:" + lp(sc.Workspace)
	default:
		want = "org:" + lp(sc.Org)
	}
	return sc, r.DomainKey == want
}
