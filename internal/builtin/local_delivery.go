package builtin

import (
	"context"

	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// SealMaterial resolves only a frozen builtin reference still active in the
// same catalog store and owner scope. It returns only HPKE ciphertext.
func (l *Local) SealMaterial(ctx context.Context, s dispatch.Snapshot, recipient []byte) (runnerproto.ValueEnvelope, error) {
	if l == nil || l.pool == nil || s.Job.Validate() != nil || s.Job.Secret.Provider != runnerproto.ProviderBuiltin || s.ProviderVersion != s.Job.ExpectedVersion {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var owner, scope tenancy.Scope
	err = tx.QueryRow(ctx, `SELECT st.owner_scope_level,st.owner_scope_id,s.scope_level,s.scope_id
	 FROM secrets s JOIN stores st ON st.org_id=s.org_id AND st.id=s.store_id
	 JOIN secret_versions v ON v.org_id=s.org_id AND v.secret_id=s.id
	 WHERE s.org_id=$1 AND s.id=$2 AND v.id=$3 AND st.id=$4 AND st.provider='builtin'
	 AND s.status='active' AND st.status='active' AND v.disabled=false
	 AND s.provider_ref=$5 AND v.provider_version=$6 AND v.fingerprint=$7 AND s.name=$8 AND s.class=$9
	 FOR SHARE OF s,st,v`,
		s.Job.OrgID, s.SecretID, s.VersionID, s.Job.Secret.StoreID, s.ProviderRef, s.ProviderVersion, s.Job.ExpectedFingerprint, s.Job.Secret.Name, s.Job.Secret.Scope).Scan(&owner.Level, &owner.ID, &scope.Level, &scope.ID)
	if err != nil || owner != s.OwnerScope || scope != s.SecretScope {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	var workspace, project, user string
	switch owner.Level {
	case tenancy.LevelOrg:
		if owner.ID.String() != s.Job.OrgID {
			return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
		}
	case tenancy.LevelWorkspace:
		workspace = owner.ID.String()
	case tenancy.LevelProject:
		project = owner.ID.String()
		if err := tx.QueryRow(ctx, `SELECT workspace_id::text FROM projects WHERE org_id=$1 AND id=$2`, s.Job.OrgID, owner.ID).Scan(&workspace); err != nil {
			return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
		}
	case tenancy.LevelUser:
		user = owner.ID.String()
	default:
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	// All reads use the lock-holding transaction, including sealer lookups,
	// so concurrent deliveries cannot exhaust the pool borrowing twice.
	p := l.Provider(s.Job.OrgID, workspace, project, user)
	p.db = p.db.withTx(tx)
	p.seal = p.seal.WithStore(p.db)
	if s.Job.NeedsFingerprintKey() {
		// A verify job gets the key that produced the frozen fingerprint and
		// nothing else: the value is never resolved, let alone sealed.
		k, err := frozenFingerprintKey(ctx, p)
		if err != nil {
			return runnerproto.ValueEnvelope{}, err
		}
		defer k.Wipe()
		return SealRunnerKey(s.Job, recipient, k)
	}
	v, meta, err := p.Resolve(ctx, provider.Ref{Path: s.ProviderRef, Version: s.ProviderVersion})
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	defer v.Wipe()
	if meta.Version != s.Job.ExpectedVersion {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	k, err := frozenFingerprintKey(ctx, p)
	if err != nil {
		return runnerproto.ValueEnvelope{}, err
	}
	defer k.Wipe()
	return SealRunnerMaterial(s.Job, recipient, v, k)
}

// frozenFingerprintKey is the key that produced the frozen fingerprint.
// Delivery never creates a replacement key while serving an existing job.
func frozenFingerprintKey(ctx context.Context, p *Provider) (fingerprint.Key, error) {
	keyRow, err := p.db.byVersion(ctx, p.scope, fpKeySecretID, 1)
	if err != nil {
		return fingerprint.Key{}, ErrDeliveryMaterial
	}
	k, err := p.openFingerprintKey(ctx, keyRow)
	if err != nil {
		return fingerprint.Key{}, ErrDeliveryMaterial
	}
	return k, nil
}
