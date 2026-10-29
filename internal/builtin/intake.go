package builtin

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/cloudflare/circl/hpke"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Write always seals Name=Path. A distinct authenticated name proves the
// bundle was sealed by the server intake path. Legacy Name=Path bundles
// are ambiguous and fail closed; do not migrate them into trusted keys.
const intakeKeyName = "keep/server-intake-key/v1"

const intakeKeySecretID = "__keep_intake_key__" // #nosec G101 -- reserved storage id

// intakeKeys never leave the plaintext zone. A store keeps one sealed bundle
// containing its X25519 receiver and Ed25519 descriptor signing keys.
func (p *Provider) intakeKeys(ctx context.Context) (secret.Value, error) {
	row, err := p.db.byVersion(ctx, p.scope, intakeKeySecretID, 1)
	if err == nil {
		if row.name != intakeKeyName {
			return secret.Value{}, errors.New("builtin: untrusted intake key")
		}
		return p.seal.Open(ctx, sealer.Ref{Store: p.scope, SecretID: intakeKeySecretID, Name: intakeKeyName, Version: "1"}, sealer.Envelope{KEKID: row.kekID, WrappedDEK: row.wrapped, Ciphertext: row.cipher})
	}
	if !errors.Is(err, errNotFound) {
		return secret.Value{}, errors.New("builtin: intake key lookup failed")
	}
	_, sk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		return secret.Value{}, errors.New("builtin: generate intake key failed")
	}
	raw, err := sk.MarshalBinary()
	if err != nil {
		return secret.Value{}, errors.New("builtin: encode intake key failed")
	}
	defer clear(raw)
	_, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		return secret.Value{}, errors.New("builtin: generate intake signer failed")
	}
	defer clear(signer)
	bundle := append(raw, signer...)
	defer clear(bundle)
	value := secret.New(bundle)
	tx, err := p.db.pool.BeginTx(ctx, readCommitted)
	if err != nil {
		value.Wipe()
		return secret.Value{}, errors.New("builtin: begin intake key failed")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, levelLockKey(p.scope.Org)); err != nil {
		value.Wipe()
		return secret.Value{}, errors.New("builtin: lock intake key failed")
	}
	txStore := p.db.withTx(tx)
	env, err := p.seal.WithStore(txStore).Seal(ctx, sealer.Ref{Store: p.scope, SecretID: intakeKeySecretID, Name: intakeKeyName, Version: "1"}, value)
	if err != nil {
		value.Wipe()
		return secret.Value{}, errors.New("builtin: seal intake key failed")
	}
	inserted, err := txStore.insertIfAbsent(ctx, p.scope, intakeKeySecretID, intakeKeyName, 1, env)
	if err != nil {
		value.Wipe()
		return secret.Value{}, errors.New("builtin: store intake key failed")
	}
	if !inserted {
		value.Wipe()
		_ = tx.Rollback(ctx)
		return p.intakeKeys(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		value.Wipe()
		return secret.Value{}, errors.New("builtin: commit intake key failed")
	}
	return value, nil
}

// IntakeDescriptor signs the public receiver key, request and visible metadata.
// The caller conveys the signing key on the authenticated link
// issuance channel; a page must verify before encrypting any input.
func (p *Provider) IntakeDescriptor(ctx context.Context, requestID string, metadata descriptor.Metadata) (public, signing, signature []byte, err error) {
	if !validIntakeRequestID(requestID) {
		return nil, nil, nil, errors.New("builtin: invalid intake request")
	}
	key, err := p.intakeKeys(ctx)
	if err != nil {
		return nil, nil, nil, errors.New("builtin: intake key unavailable")
	}
	defer key.Wipe()
	fk, err := p.FingerprintKey(ctx)
	if err != nil {
		return nil, nil, nil, errors.New("builtin: fingerprint key unavailable")
	}
	fk.Wipe()
	secret.Expose(key, func(raw []byte) {
		if len(raw) != 32+ed25519.PrivateKeySize {
			err = errors.New("builtin: invalid intake key")
			return
		}
		sk, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(raw[:32])
		if e != nil {
			err = errors.New("builtin: invalid intake key")
			return
		}
		public, e = sk.Public().MarshalBinary()
		if e != nil {
			err = errors.New("builtin: invalid intake key")
			return
		}
		signer := ed25519.PrivateKey(raw[32:])
		signing = append([]byte(nil), signer.Public().(ed25519.PublicKey)...)
		signature = ed25519.Sign(signer, descriptor.Message(requestID, public, metadata))
	})
	return public, signing, signature, err
}

// AcceptIntake opens a single HPKE message and seals a new version within
// tx. The caller commits the envelope together with link consumption and
// catalog metadata. No plaintext leaves this method.
func (p *Provider) AcceptIntake(ctx context.Context, tx pgx.Tx, requestID, path string, enc, ciphertext []byte) (version, fp string, length int, err error) {
	fail := errors.New("builtin: intake rejected")
	if p.checkAvailable(ctx) != nil {
		return "", "", 0, fail
	}
	if tx == nil || len(enc) != 32 || len(ciphertext) < 16 || len(ciphertext) > 1048592 {
		return "", "", 0, fail
	}
	if !validIntakeRequestID(requestID) {
		return "", "", 0, fail
	}
	if pathErr(path) != nil {
		return "", "", 0, fail
	}
	db := p.db.withTx(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, levelLockKey(p.scope.Org)); err != nil {
		return "", "", 0, fail
	}
	row, err := db.byVersion(ctx, p.scope, intakeKeySecretID, 1)
	if err != nil || row.name != intakeKeyName {
		return "", "", 0, fail
	}
	seal := p.seal.WithStore(db)
	key, err := seal.Open(ctx, sealer.Ref{Store: p.scope, SecretID: intakeKeySecretID, Name: intakeKeyName, Version: "1"}, sealer.Envelope{KEKID: row.kekID, WrappedDEK: row.wrapped, Ciphertext: row.cipher})
	if err != nil {
		return "", "", 0, fail
	}
	defer key.Wipe()
	var plain []byte
	var openErr error
	secret.Expose(key, func(raw []byte) {
		if len(raw) != 32+ed25519.PrivateKeySize {
			openErr = fail
			return
		}
		sk, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(raw[:32])
		if e != nil {
			openErr = fail
			return
		}
		suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
		receiver, e := suite.NewReceiver(sk, []byte("keep/intake/v1\x00"+requestID))
		if e != nil {
			openErr = fail
			return
		}
		opener, e := receiver.Setup(enc)
		if e != nil {
			openErr = fail
			return
		}
		plain, openErr = opener.Open(ciphertext, nil)
	})
	defer clear(plain)
	if openErr != nil {
		return "", "", 0, fail
	}
	value := secret.New(plain)
	defer value.Wipe()
	n, err := nextVersion(ctx, tx, p.scope, path)
	if err != nil {
		return "", "", 0, fail
	}
	version = versionString(n)
	env, err := seal.Seal(ctx, sealer.Ref{Store: p.scope, SecretID: path, Name: path, Version: version}, value)
	if err != nil {
		return "", "", 0, fail
	}
	fpRow, err := db.byVersion(ctx, p.scope, fpKeySecretID, 1)
	if err != nil {
		return "", "", 0, fail
	}
	txProvider := &Provider{scope: p.scope, seal: seal, db: db, log: p.log}
	fk, err := txProvider.openFingerprintKey(ctx, fpRow)
	if err != nil {
		return "", "", 0, fail
	}
	defer fk.Wipe()
	fp, err = fingerprint.Compute(fk, value)
	if err != nil {
		return "", "", 0, fail
	}
	inserted, err := db.insertIfAbsent(ctx, p.scope, path, path, n, env)
	if err != nil || !inserted {
		return "", "", 0, fail
	}
	p.log.Info("intake sealed", "version_id", version)
	return version, fp, value.Len(), nil
}

func validIntakeRequestID(requestID string) bool {
	id, err := uuid.Parse(requestID)
	return err == nil && id.String() == requestID && id.Version() == 7 && id.Variant() == uuid.RFC4122
}
