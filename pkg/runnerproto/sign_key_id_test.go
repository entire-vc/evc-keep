package runnerproto

import "testing"

func TestSigningKeyIDEnrollmentCompatibility(t *testing.T) {
	k := newKeys(t)
	k.signer.KeyID = "orgsign_0123456789abcdef"
	if _, err := k.signer.Sign(deployJob(t)); err != nil {
		t.Fatal("enrolled signing key identifier was rejected")
	}
	for _, bad := range []string{"", "../key", "key\n", "key value", "Key", string(make([]byte, 65))} {
		k.signer.KeyID = bad
		if _, err := k.signer.Sign(deployJob(t)); err == nil {
			t.Fatal("invalid signing key identifier accepted")
		}
	}
}
