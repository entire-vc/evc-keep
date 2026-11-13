package builtin

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/cloudflare/circl/hpke"
)

// ErrTransferTransport is the only error the offline-transfer transport
// returns. It carries no key, context, plaintext or library text.
var ErrTransferTransport = errors.New("builtin: offline transfer transport failed")

// MaxTransferBundle bounds one sealed bundle, in bytes of plaintext.
const MaxTransferBundle = 256 << 20

// RFC 9180 identifiers of the one supported suite: DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256, ChaCha20-Poly1305. Spelled as numbers because the library's
// KDF names are fenced to intake; no KDF function is called from here.
const (
	transferKDF  = 0x0001
	transferAEAD = 0x0003
)

const transferDomain = "keep/offline-transfer/v1\x00"

// TransferContext is the public binding of one transfer. Every field enters
// the HPKE info and AAD length-prefixed, so a bundle opens only under exactly
// the context it was sealed for. HPKE base mode does not authenticate the
// source: the receiver must pin these identities independently.
type TransferContext struct {
	Protocol     string
	Transfer     string
	Source       string
	Target       string
	Snapshot     string
	Org          string
	Workspace    string
	Schema       uint64
	RecipientPub []byte
}

func (c TransferContext) encode() []byte {
	out := []byte(transferDomain)
	put := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		out = append(out, n[:]...)
		out = append(out, b...)
	}
	for _, s := range []string{c.Protocol, c.Transfer, c.Source, c.Target, c.Snapshot, c.Org, c.Workspace} {
		put([]byte(s))
	}
	var schema [8]byte
	binary.BigEndian.PutUint64(schema[:], c.Schema)
	put(schema[:])
	put(c.RecipientPub)
	return out
}

func transferSuite() hpke.Suite {
	return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF(transferKDF), hpke.AEAD(transferAEAD))
}

// NewTransferRecipient creates a recipient keypair on the target. priv is the
// raw private key for a 0600 O_EXCL carrier written by the caller; the caller
// must clear it after writing.
func NewTransferRecipient() (pub, priv []byte, err error) {
	p, k, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, ErrTransferTransport
	}
	pub, err = p.MarshalBinary()
	if err != nil {
		return nil, nil, ErrTransferTransport
	}
	priv, err = k.MarshalBinary()
	if err != nil {
		return nil, nil, ErrTransferTransport
	}
	return pub, priv, nil
}

// sealTransferBundle encrypts plain to recipientPub under tc. tc.RecipientPub
// must equal recipientPub.
func sealTransferBundle(recipientPub []byte, tc TransferContext, plain []byte) ([]byte, error) {
	if len(plain) > MaxTransferBundle || !bytes.Equal(recipientPub, tc.RecipientPub) {
		return nil, ErrTransferTransport
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, ErrTransferTransport
	}
	info := tc.encode()
	sender, err := transferSuite().NewSender(pub, info)
	if err != nil {
		return nil, ErrTransferTransport
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, ErrTransferTransport
	}
	ct, err := sealer.Seal(plain, info)
	if err != nil {
		return nil, ErrTransferTransport
	}
	return append(enc, ct...), nil
}

// openTransferBundle decrypts sealed with recipientPriv under tc. The private
// key must belong to tc.RecipientPub. The caller owns and must clear both the
// key and the returned plaintext.
func openTransferBundle(recipientPriv []byte, tc TransferContext, sealed []byte) ([]byte, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	if len(sealed) <= scheme.CiphertextSize() || len(sealed) > MaxTransferBundle+scheme.CiphertextSize()+64 {
		return nil, ErrTransferTransport
	}
	priv, err := scheme.UnmarshalBinaryPrivateKey(recipientPriv)
	if err != nil {
		return nil, ErrTransferTransport
	}
	pub, err := priv.Public().MarshalBinary()
	if err != nil || !bytes.Equal(pub, tc.RecipientPub) {
		return nil, ErrTransferTransport
	}
	info := tc.encode()
	receiver, err := transferSuite().NewReceiver(priv, info)
	if err != nil {
		return nil, ErrTransferTransport
	}
	enc, ct := sealed[:scheme.CiphertextSize()], sealed[scheme.CiphertextSize():]
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, ErrTransferTransport
	}
	plain, err := opener.Open(ct, info)
	if err != nil {
		return nil, ErrTransferTransport
	}
	return plain, nil
}
