package runnerproto

import (
	"bytes"
	"testing"
	"time"
)

func TestVerifyKeyInfoIsItsOwnDomainBoundToNonceAndWindow(t *testing.T) {
	j := deployJob(t)
	got := VerifyKeyInfo(j)
	if !bytes.HasPrefix(got, []byte("keep/fingerprint-key/verify/v1\x00")) {
		t.Fatal("verify key info lost its domain label")
	}
	for name, other := range map[string][]byte{"value": Info(j), "deploy key": FingerprintKeyInfo(j)} {
		if bytes.HasPrefix(got, other) || bytes.HasPrefix(other, got) {
			t.Fatalf("verify key info shares a prefix with the %s info", name)
		}
	}
	if !bytes.Equal(got, VerifyKeyInfo(j)) {
		t.Fatal("verify key info is not deterministic")
	}
	for name, change := range map[string]func(*Job){
		"nonce":     func(x *Job) { x.Nonce = append([]byte(nil), x.Nonce...); x.Nonce[0] ^= 1 },
		"issued_at": func(x *Job) { x.IssuedAt = x.IssuedAt.Add(time.Second) },
		"not_after": func(x *Job) { x.NotAfter = x.NotAfter.Add(time.Second) },
		"job_id":    func(x *Job) { x.JobID += "x" },
	} {
		c := j
		change(&c)
		if bytes.Equal(VerifyKeyInfo(c), got) {
			t.Fatalf("verify key info does not bind %s", name)
		}
	}
}
