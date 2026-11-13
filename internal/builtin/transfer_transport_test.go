package builtin

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func transferFixture(t *testing.T) (pub, priv []byte, tc TransferContext) {
	t.Helper()
	pub, priv, err := NewTransferRecipient()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, TransferContext{Protocol: "p1", Transfer: "t", Source: "s", Target: "g", Snapshot: "n", Org: "o", Workspace: "w", Schema: 48, RecipientPub: pub}
}

func TestTransferTransportRoundTripAndBinding(t *testing.T) {
	pub, priv, tc := transferFixture(t)
	canary := make([]byte, 40)
	_, _ = rand.Read(canary)
	sealed, err := sealTransferBundle(pub, tc, canary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, canary) {
		t.Fatal("plaintext visible in sealed bundle")
	}
	got, err := openTransferBundle(priv, tc, sealed)
	if err != nil || !bytes.Equal(got, canary) {
		t.Fatalf("positive control failed: %v", err)
	}

	otherPub, otherPriv, _ := transferFixture(t)
	mut := map[string]func(c *TransferContext){
		"protocol": func(c *TransferContext) { c.Protocol += "x" }, "transfer": func(c *TransferContext) { c.Transfer += "x" },
		"source": func(c *TransferContext) { c.Source += "x" }, "target": func(c *TransferContext) { c.Target += "x" },
		"snapshot": func(c *TransferContext) { c.Snapshot += "x" }, "org": func(c *TransferContext) { c.Org += "x" },
		"workspace": func(c *TransferContext) { c.Workspace += "x" }, "schema": func(c *TransferContext) { c.Schema++ },
		"recipient": func(c *TransferContext) { c.RecipientPub = otherPub },
		// field boundary shift must not collide: ("p1","t") vs ("p","1t")
		"boundary": func(c *TransferContext) { c.Protocol, c.Transfer = "p", "1t" },
	}
	for name, f := range mut {
		c := tc
		f(&c)
		if _, err := openTransferBundle(priv, c, sealed); err != ErrTransferTransport {
			t.Errorf("%s: context change accepted or wrong error: %v", name, err)
		}
	}
	if _, err := openTransferBundle(otherPriv, tc, sealed); err != ErrTransferTransport {
		t.Error("wrong recipient key accepted")
	}
	for i := range sealed {
		b := append([]byte(nil), sealed...)
		b[i] ^= 1
		if _, err := openTransferBundle(priv, tc, b); err != ErrTransferTransport {
			t.Fatalf("tamper at byte %d accepted", i)
		}
	}
	for _, n := range []int{0, 1, 31, 32, 33} {
		if _, err := openTransferBundle(priv, tc, sealed[:n]); err != ErrTransferTransport {
			t.Errorf("truncation to %d accepted", n)
		}
	}
	if _, err := sealTransferBundle(otherPub, tc, canary); err != ErrTransferTransport {
		t.Error("seal accepted a recipient that differs from the context")
	}
	for _, e := range []error{ErrTransferTransport} {
		for _, s := range []string{e.Error(), fmt.Sprintf("%+v", e), fmt.Sprintf("%#v", e)} {
			if bytes.Contains([]byte(s), canary) || bytes.Contains([]byte(s), priv) {
				t.Fatal("error exposes material")
			}
		}
	}
}
