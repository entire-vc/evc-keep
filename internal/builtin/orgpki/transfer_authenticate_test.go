package orgpki

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/google/uuid"
)

type transferCAFx struct {
	org    uuid.UUID
	rows   *store.TransferRows
	target builtin.TransferRoot
}

// newTransferCAFx makes a real org CA under a source root, rewraps its KEK
// closure to an independent target root, and lays both out as transfer rows.
func newTransferCAFx(t *testing.T) transferCAFx {
	t.Helper()
	ctx := context.Background()
	key := func() []byte {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	srcRoot, err := sealer.NewLocalRootKey("src-root", key())
	if err != nil {
		t.Fatal(err)
	}
	dstKey := key()
	dstRoot, err := sealer.NewLocalRootKey("dst-root", bytes.Clone(dstKey))
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "root")
	if err := os.WriteFile(f, []byte(base64.StdEncoding.EncodeToString(dstKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := builtin.OpenTransferRoot(f, "dst-root")
	if err != nil {
		t.Fatal(err)
	}
	st := newMemStore()
	s := sealer.New(srcRoot, noopAuditor{}, st)
	org := uuid.New()
	rec, err := generate(ctx, org, s)
	if err != nil {
		t.Fatal(err)
	}
	var keks []store.KEKRow
	for _, r := range st.recs {
		moved, err := sealer.RewrapKEK(r.Org, r, srcRoot, dstRoot)
		if err != nil {
			t.Fatal(err)
		}
		keks = append(keks, store.KEKRow{
			ID: moved.ID, OrgID: moved.Org, DomainKey: "pki:" + strconv.Itoa(len(moved.Domain.Org)) + ":" + moved.Domain.Org,
			DomainOrg: moved.Domain.Org, RootKeyID: moved.RootKeyID, Wrapped: moved.Wrapped, State: "active",
		})
	}
	return transferCAFx{
		org: org, target: target,
		rows: &store.TransferRows{KEKs: keks, OrgCAs: []store.OrgCARow{{
			OrgID: org, CACertDER: rec.caCertDER, CAKEKID: rec.caEnv.KEKID, CAWrappedDEK: rec.caEnv.WrappedDEK, CACiphertext: rec.caEnv.Ciphertext,
			SignKeyID: rec.signKeyID, SignPubKey: rec.signPubKey, SignKEKID: rec.signEnv.KEKID, SignWrappedDEK: rec.signEnv.WrappedDEK, SignCiphertext: rec.signEnv.Ciphertext,
		}}},
	}
}

func TestAuthenticateTransferCA(t *testing.T) {
	ctx := context.Background()
	f := newTransferCAFx(t)
	if err := AuthenticateTransferCA(ctx, f.org, f.rows, f.target); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if len(f.rows.KEKs) != 1 {
		t.Fatalf("the PKI domain should hold one KEK, got %d", len(f.rows.KEKs))
	}
	if err := AuthenticateTransferCA(ctx, f.org, &store.TransferRows{}, f.target); err != nil {
		t.Fatalf("a transfer without org_ca has nothing to prove: %v", err)
	}
	clone := func(mut func(r *store.TransferRows)) *store.TransferRows {
		c := *f.rows
		c.KEKs = append([]store.KEKRow(nil), f.rows.KEKs...)
		c.OrgCAs = append([]store.OrgCARow(nil), f.rows.OrgCAs...)
		mut(&c)
		return &c
	}
	flipb := func(b []byte) []byte { c := bytes.Clone(b); c[len(c)-1] ^= 1; return c }
	cases := map[string]*store.TransferRows{
		"tampered ca ciphertext": clone(func(r *store.TransferRows) { r.OrgCAs[0].CACiphertext = flipb(r.OrgCAs[0].CACiphertext) }),
		"tampered sign envelope": clone(func(r *store.TransferRows) { r.OrgCAs[0].SignWrappedDEK = flipb(r.OrgCAs[0].SignWrappedDEK) }),
		"foreign org row":        clone(func(r *store.TransferRows) { r.OrgCAs[0].OrgID = uuid.New() }),
		"two org_ca rows":        clone(func(r *store.TransferRows) { r.OrgCAs = append(r.OrgCAs, r.OrgCAs[0]) }),
		"kek not rewrapped":      clone(func(r *store.TransferRows) { r.KEKs[0].RootKeyID = "src-root" }),
		"missing kek":            clone(func(r *store.TransferRows) { r.KEKs = nil }),
		"kek of a user domain":   clone(func(r *store.TransferRows) { r.KEKs[0].DomainKey = "org:1:x/user:1:y"; r.KEKs[0].DomainUser = "y" }),
		"kek of another org":     clone(func(r *store.TransferRows) { r.KEKs[0].DomainOrg = uuid.NewString() }),
		"kek with a workspace":   clone(func(r *store.TransferRows) { r.KEKs[0].DomainWorkspace = "w" }),
		"wrapped kek tampered":   clone(func(r *store.TransferRows) { r.KEKs[0].Wrapped = flipb(r.KEKs[0].Wrapped) }),
		"nil rows":               nil,
	}
	for name, rows := range cases {
		err := AuthenticateTransferCA(ctx, f.org, rows, f.target)
		if !errors.Is(err, ErrRowNotAuthentic) || err.Error() != ErrRowNotAuthentic.Error() {
			t.Errorf("%s: want bare ErrRowNotAuthentic, got %v", name, err)
		}
	}
	var zero builtin.TransferRoot
	if err := AuthenticateTransferCA(ctx, f.org, f.rows, zero); !errors.Is(err, ErrRowNotAuthentic) {
		t.Errorf("zero target root: %v", err)
	}
	other := newTransferCAFx(t)
	if err := AuthenticateTransferCA(ctx, f.org, f.rows, other.target); !errors.Is(err, ErrRowNotAuthentic) {
		t.Errorf("a different target root must not open it: %v", err)
	}
}

// The domain check is also enforced by AAD authentication for honest data;
// it is tested on its own so a hostile source that relabels a KEK is refused
// by the check itself, not only by the failure that usually follows.
func TestIsOrgPKIKEK(t *testing.T) {
	org := uuid.New()
	pki := func() store.KEKRow {
		return store.KEKRow{ID: "k", OrgID: org.String(), DomainOrg: org.String(), DomainKey: "pki:36:" + org.String()}
	}
	if !isOrgPKIKEK([]store.KEKRow{pki()}, "k", org) {
		t.Fatal("positive control: the org's PKI KEK was refused")
	}
	for name, mut := range map[string]func(*store.KEKRow){
		"org domain key":   func(r *store.KEKRow) { r.DomainKey = "org:36:" + org.String() },
		"foreign org":      func(r *store.KEKRow) { r.OrgID = uuid.NewString() },
		"foreign domain":   func(r *store.KEKRow) { r.DomainOrg = uuid.NewString() },
		"workspace set":    func(r *store.KEKRow) { r.DomainWorkspace = "w" },
		"project set":      func(r *store.KEKRow) { r.DomainProject = "p" },
		"user set":         func(r *store.KEKRow) { r.DomainUser = "u" },
		"empty domain key": func(r *store.KEKRow) { r.DomainKey = "" },
	} {
		r := pki()
		mut(&r)
		if isOrgPKIKEK([]store.KEKRow{r}, "k", org) {
			t.Errorf("%s: accepted", name)
		}
	}
	if isOrgPKIKEK([]store.KEKRow{pki()}, "other-id", org) || isOrgPKIKEK(nil, "k", org) {
		t.Error("an absent KEK was accepted")
	}
}
