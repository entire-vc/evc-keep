package runnerproto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestFingerprintEnvelopeDomain(t *testing.T) {
	j := deployJob(t)
	const domain = "keep/fingerprint-key/v1\x00"
	want := append([]byte(domain), Info(j)...)
	if !bytes.Equal(FingerprintKeyInfo(j), want) {
		t.Fatal("fingerprint envelope domain or full binding differs")
	}
}

func TestFingerprintEnvelopeCannotSwapWithValue(t *testing.T) {
	j := deployJob(t)
	suite := hpke.NewSuite(hpke.KEM(HPKEKEM), hpke.KDF(HPKEKDF), hpke.AEAD(HPKEAEAD))
	pub, priv, err := hpke.KEM(HPKEKEM).Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal("generate recipient")
	}
	for _, tc := range []struct {
		name     string
		from, to []byte
	}{
		{"key_as_value", FingerprintKeyInfo(j), Info(j)},
		{"value_as_key", Info(j), FingerprintKeyInfo(j)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, err := suite.NewSender(pub, tc.from)
			if err != nil {
				t.Fatal("sender")
			}
			enc, sealer, err := sender.Setup(rand.Reader)
			if err != nil {
				t.Fatal("setup sender")
			}
			plain := make([]byte, 32)
			defer clear(plain)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal("generate material")
			}
			cipher, err := sealer.Seal(plain, nil)
			if err != nil {
				t.Fatal("seal material")
			}
			open := func(info []byte) ([]byte, error) {
				receiver, err := suite.NewReceiver(priv, info)
				if err != nil {
					return nil, err
				}
				opener, err := receiver.Setup(enc)
				if err != nil {
					return nil, err
				}
				return opener.Open(cipher, nil)
			}
			out, err := open(tc.from)
			matched := err == nil && bytes.Equal(out, plain)
			clear(out)
			if !matched {
				t.Fatal("matching envelope failed")
			}
			out, err = open(tc.to)
			clear(out)
			if err == nil {
				t.Fatal("swapped envelope accepted")
			}
		})
	}
}
