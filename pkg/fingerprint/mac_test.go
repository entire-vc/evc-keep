package fingerprint

import (
	"encoding/hex"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// RFC 4231 test case 2: MAC must be plain HMAC-SHA256, so the Mesh side can
// compute the same tag with any standard library.
func TestMACMatchesRFC4231(t *testing.T) {
	v := secret.New([]byte("Jefe"))
	got := hex.EncodeToString(mac(v, []byte("what do ya want for nothing?")))
	const want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if got != want {
		t.Fatalf("MAC = %s, want %s", got, want)
	}
}

func TestVerifyMAC(t *testing.T) {
	v := secret.New([]byte("Jefe"))
	msg := []byte("what do ya want for nothing?")
	tag, _ := hex.DecodeString("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	if !VerifyMAC(v, msg, tag) {
		t.Fatal("valid tag refused")
	}
	bad := append([]byte(nil), tag...)
	bad[0] ^= 1
	for name, c := range map[string]struct {
		v   secret.Value
		msg []byte
		tag []byte
	}{
		"flipped bit": {v, msg, bad}, "other message": {v, []byte("x"), tag}, "other key": {secret.New([]byte("Jefe2")), msg, tag},
		"truncated": {v, msg, tag[:31]}, "empty tag": {v, msg, nil},
	} {
		if VerifyMAC(c.v, c.msg, c.tag) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMACDependsOnKeyAndMessage(t *testing.T) {
	a := mac(secret.New([]byte("key-a-key-a-key-a")), []byte("m"))
	b := mac(secret.New([]byte("key-b-key-b-key-b")), []byte("m"))
	c := mac(secret.New([]byte("key-a-key-a-key-a")), []byte("n"))
	if hex.EncodeToString(a) == hex.EncodeToString(b) || hex.EncodeToString(a) == hex.EncodeToString(c) {
		t.Fatal("MAC ignores its key or its message")
	}
}
