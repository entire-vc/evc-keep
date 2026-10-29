package fingerprint

import (
	"encoding/hex"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// FIPS 180-2 example: SHA-256("abc").
const abcSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestMatchSHA256(t *testing.T) {
	var want [32]byte
	if _, err := hex.Decode(want[:], []byte(abcSHA256)); err != nil {
		t.Fatal(err)
	}
	v := secret.New([]byte("abc"))
	if !MatchSHA256(v, want) {
		t.Fatal("the digest of the value refused")
	}
	for name, mutate := range map[string]func(*[32]byte){
		"first byte":  func(d *[32]byte) { d[0] ^= 1 },
		"last byte":   func(d *[32]byte) { d[31] ^= 1 },
		"middle byte": func(d *[32]byte) { d[16] ^= 0x80 },
		"prefix only": func(d *[32]byte) { clear(d[4:]) },
		"zero":        func(d *[32]byte) { *d = [32]byte{} },
	} {
		d := want
		mutate(&d)
		if MatchSHA256(v, d) {
			t.Errorf("%s: accepted", name)
		}
	}
	if MatchSHA256(secret.New([]byte("abd")), want) {
		t.Error("another value accepted")
	}
}
