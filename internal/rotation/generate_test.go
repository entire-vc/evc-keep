package rotation

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	prot "github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

func TestGeneratorIssuesFreshValidKeys(t *testing.T) {
	key, err := fingerprint.GenerateKey("test")
	if err != nil {
		t.Fatal("key")
	}
	defer key.Wipe()
	fp := func(g Generator) (string, prot.Issued) {
		iss, err := g.Issue(context.Background(), prot.IssueRequest{Subject: "s", RunID: uuid.New()})
		if err != nil || !prot.ValidKeyID(iss.KeyID) || iss.Value.IsZero() {
			t.Fatal("issue must give a valid key and a value")
		}
		f, err := fingerprint.Compute(key, iss.Value)
		if err != nil {
			t.Fatal("fingerprint")
		}
		return f, iss
	}
	f1, a := fp(Generator{})
	f2, b := fp(Generator{})
	if f1 == f2 || a.KeyID == b.KeyID || a.Value.Len() != 43 {
		t.Fatal("each issue must give a distinct key and value of 256 bits")
	}
	// A known entropy source gives a known value: the seam the end-to-end
	// tests use to look for it on every surface.
	ent := bytes.Repeat([]byte{7}, 32)
	f3, _ := fp(Generator{Entropy: bytes.NewReader(ent)})
	want, err := fingerprint.Compute(key, secret.New([]byte(base64.RawURLEncoding.EncodeToString(ent))))
	if err != nil || f3 != want {
		t.Fatal("value is not the base64url of the entropy read")
	}
	if _, err := (Generator{Entropy: bytes.NewReader(ent[:5])}).Issue(context.Background(), prot.IssueRequest{}); err == nil {
		t.Fatal("a short entropy source must fail, not issue a weak value")
	}
	if st, err := (Generator{}).Check(context.Background(), a.KeyID); err != nil || st.Active {
		t.Fatal("a generated key is never active")
	}
}

func TestRunIDRoundTrip(t *testing.T) {
	id := uuid.New()
	got, ok := RunID(withRunID(context.Background(), id))
	if !ok || got != id {
		t.Fatal("run id lost")
	}
	if _, ok := RunID(context.Background()); ok {
		t.Fatal("no run id expected on a bare context")
	}
}
