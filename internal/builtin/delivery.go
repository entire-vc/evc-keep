package builtin

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/hpke"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// ErrDeliveryMaterial deliberately excludes underlying errors and input text.
var ErrDeliveryMaterial = errors.New("builtin: runner material unavailable")

// SealRunnerMaterial produces ciphertext only. The transport must first claim
// the immutable authorized job atomically and supply its registered recipient.
// The caller owns and wipes value and key; this function retains neither.
// External providers receive only the fingerprint key, never a server value.
func SealRunnerMaterial(j runnerproto.Job, recipient []byte, value secret.Value, key fingerprint.Key) (runnerproto.ValueEnvelope, error) {
	if j.Validate() != nil || !j.NeedsValue() {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	parsed, err := fingerprint.Parse(j.ExpectedFingerprint)
	if err != nil || parsed.KeyID != key.ID() {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	// Validate liveness even for an external provider, where no value is held.
	if _, err := fingerprint.Compute(key, secret.Value{}); err != nil {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	if j.Secret.Provider == runnerproto.ProviderBuiltin {
		actual, err := fingerprint.Compute(key, value)
		if err != nil || actual != j.ExpectedFingerprint {
			return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
		}
	}
	env := runnerproto.ValueEnvelope{JobID: j.JobID}
	fingerprint.ExposeKey(key, func(raw []byte) {
		if len(raw) != fingerprint.KeySize {
			err = ErrDeliveryMaterial
			return
		}
		env.SealedFingerprintKey, err = sealRunnerBytes(recipient, runnerproto.FingerprintKeyInfo(j), raw)
	})
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	if j.Secret.Provider == runnerproto.ProviderBuiltin {
		secret.Expose(value, func(raw []byte) { env.Sealed, err = sealRunnerBytes(recipient, runnerproto.Info(j), raw) })
	}
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	return env, nil
}

// OpenRunnerMaterial is the runner's side of SealRunnerMaterial: it opens both
// envelopes with the runner's registered delivery key, each under its own
// info string, and returns the value and the fingerprint key. It does not
// compare the value with the job's fingerprint; the caller must, before the
// value is written anywhere. The caller wipes both results. Errors never
// carry input.
func OpenRunnerMaterial(j runnerproto.Job, recipient *ecdh.PrivateKey, env runnerproto.ValueEnvelope) (secret.Value, fingerprint.Key, error) {
	parsed, err := fingerprint.Parse(j.ExpectedFingerprint)
	if recipient == nil || err != nil || j.Validate() != nil || !j.NeedsValue() || env.JobID != j.JobID {
		return secret.Value{}, fingerprint.Key{}, ErrDeliveryMaterial
	}
	rawKey, err := openRunnerBytes(recipient, runnerproto.FingerprintKeyInfo(j), env.SealedFingerprintKey)
	defer clear(rawKey)
	if err != nil {
		return secret.Value{}, fingerprint.Key{}, ErrDeliveryMaterial
	}
	key, err := fingerprint.NewKey(parsed.KeyID, rawKey)
	if err != nil {
		return secret.Value{}, fingerprint.Key{}, ErrDeliveryMaterial
	}
	rawValue, err := openRunnerBytes(recipient, runnerproto.Info(j), env.Sealed)
	defer clear(rawValue)
	if err != nil {
		key.Wipe()
		return secret.Value{}, fingerprint.Key{}, ErrDeliveryMaterial
	}
	return secret.New(rawValue), key, nil
}

// SealRunnerKey is SealRunnerMaterial for a verify job: it seals only the
// fingerprint key, under VerifyKeyInfo, and never a value. Sealed stays empty
// whatever the provider; the caller owns and wipes key.
func SealRunnerKey(j runnerproto.Job, recipient []byte, key fingerprint.Key) (runnerproto.ValueEnvelope, error) {
	if j.Validate() != nil || !j.NeedsFingerprintKey() || j.NeedsValue() {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	parsed, err := fingerprint.Parse(j.ExpectedFingerprint)
	if err != nil || parsed.KeyID != key.ID() {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	if _, err := fingerprint.Compute(key, secret.Value{}); err != nil {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	env := runnerproto.ValueEnvelope{JobID: j.JobID}
	fingerprint.ExposeKey(key, func(raw []byte) {
		if len(raw) != fingerprint.KeySize {
			err = ErrDeliveryMaterial
			return
		}
		env.SealedFingerprintKey, err = sealRunnerBytes(recipient, runnerproto.VerifyKeyInfo(j), raw)
	})
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrDeliveryMaterial
	}
	return env, nil
}

// OpenRunnerKey is the runner's side of SealRunnerKey. An envelope that
// carries a value is refused whole: a verify job never receives one. The
// caller wipes the key. Errors never carry input.
func OpenRunnerKey(j runnerproto.Job, recipient *ecdh.PrivateKey, env runnerproto.ValueEnvelope) (fingerprint.Key, error) {
	parsed, err := fingerprint.Parse(j.ExpectedFingerprint)
	if recipient == nil || err != nil || j.Validate() != nil || !j.NeedsFingerprintKey() || env.JobID != j.JobID || len(env.Sealed) != 0 {
		return fingerprint.Key{}, ErrDeliveryMaterial
	}
	rawKey, err := openRunnerBytes(recipient, runnerproto.VerifyKeyInfo(j), env.SealedFingerprintKey)
	defer clear(rawKey)
	if err != nil {
		return fingerprint.Key{}, ErrDeliveryMaterial
	}
	key, err := fingerprint.NewKey(parsed.KeyID, rawKey)
	if err != nil {
		return fingerprint.Key{}, ErrDeliveryMaterial
	}
	return key, nil
}

func openRunnerBytes(recipient *ecdh.PrivateKey, info, sealed []byte) ([]byte, error) {
	scheme := hpke.KEM(runnerproto.HPKEKEM).Scheme()
	if recipient.Curve() != ecdh.X25519() || len(sealed) <= scheme.CiphertextSize() {
		return nil, ErrDeliveryMaterial
	}
	raw := recipient.Bytes()
	defer clear(raw)
	priv, err := scheme.UnmarshalBinaryPrivateKey(raw)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	suite := hpke.NewSuite(hpke.KEM(runnerproto.HPKEKEM), hpke.KDF(runnerproto.HPKEKDF), hpke.AEAD(runnerproto.HPKEAEAD))
	receiver, err := suite.NewReceiver(priv, info)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	enc, cipher := sealed[:scheme.CiphertextSize()], sealed[scheme.CiphertextSize():]
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	plain, err := opener.Open(cipher, nil)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	return plain, nil
}

func sealRunnerBytes(recipient, info, plain []byte) ([]byte, error) {
	pub, err := hpke.KEM(runnerproto.HPKEKEM).Scheme().UnmarshalBinaryPublicKey(recipient)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	suite := hpke.NewSuite(hpke.KEM(runnerproto.HPKEKEM), hpke.KDF(runnerproto.HPKEKDF), hpke.AEAD(runnerproto.HPKEAEAD))
	sender, err := suite.NewSender(pub, info)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	cipher, err := sealer.Seal(plain, nil)
	if err != nil {
		return nil, ErrDeliveryMaterial
	}
	return append(enc, cipher...), nil
}
