package orgpki

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrJobSigning contains no database, key, or job input details.
var ErrJobSigning = errors.New("orgpki: job signing unavailable")

// SignJob opens only the signing key for the requested organization, after
// validating the immutable job. Key bytes never leave this plaintext zone.
// A supplied transaction owns every database lookup, including sealer reads.
// With nil tx, SignJob owns a read transaction for standalone callers.
func (r *Repo) SignJob(ctx context.Context, tx pgx.Tx, org uuid.UUID, j runnerproto.Job) (runnerproto.SignedJob, error) {
	if org == uuid.Nil || j.OrgID != org.String() || j.Validate() != nil {
		return runnerproto.SignedJob{}, ErrJobSigning
	}
	if tx == nil {
		var err error
		tx, err = r.db.Begin(ctx)
		if err != nil {
			return runnerproto.SignedJob{}, ErrJobSigning
		}
		defer func() { _ = tx.Rollback(ctx) }()
	}
	rec, ok, err := loadRecordFrom(ctx, tx, org)
	if err != nil || !ok {
		return runnerproto.SignedJob{}, ErrJobSigning
	}
	v, err := r.sealer.WithStore(builtin.NewTransactionKeyStore(tx)).Open(ctx, signRef(org, rec.signKeyID, rec.signPubKey), rec.signEnv)
	if err != nil {
		return runnerproto.SignedJob{}, ErrJobSigning
	}
	defer v.Wipe()
	var signed runnerproto.SignedJob
	secret.Expose(v, func(raw []byte) {
		if len(raw) != ed25519.PrivateKeySize || len(rec.signPubKey) != ed25519.PublicKeySize {
			err = ErrJobSigning
			return
		}
		signed, err = (runnerproto.Signer{KeyID: rec.signKeyID, Key: ed25519.PrivateKey(raw)}).Sign(j)
	})
	if err != nil || !ed25519.Verify(rec.signPubKey, signed.Payload, signed.Sig) {
		return runnerproto.SignedJob{}, ErrJobSigning
	}
	return signed, nil
}
