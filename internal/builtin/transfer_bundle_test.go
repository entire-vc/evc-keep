package builtin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	kstore "github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

type bundleFixture struct {
	org, ws  string
	m        scopedtransfer.Manifest
	tc       TransferContext
	pub, prv []byte
	rows     *kstore.TransferRows
	src, dst sealer.RootKey
}

func newBundleFixture(t *testing.T) bundleFixture {
	t.Helper()
	f := bundleFixture{org: uuid.NewString(), ws: uuid.NewString()}
	f.src, _ = newRoot(t, "root")
	f.dst, _ = newRoot(t, "root")
	in := scopedtransfer.Inventory{
		OrgID: f.org, WorkspaceID: f.ws, WorkspaceIDs: []string{f.ws},
		Providers: []string{"builtin"}, MeshMode: "store", SchemaVersion: scopedtransfer.SchemaVersion,
		MigrationSetID: scopedtransfer.MigrationSetID, CatalogID: scopedtransfer.CatalogID,
	}
	for _, p := range scopedtransfer.TablePolicies() {
		var n int64
		if p.Disposition == scopedtransfer.CopyRows || p.Disposition == scopedtransfer.RewrapRows {
			n = 1
		}
		in.Tables = append(in.Tables, scopedtransfer.TableCount{Name: p.Name, Rows: n})
	}
	f.m = scopedtransfer.Manifest{
		Version: scopedtransfer.ManifestVersion, ProfileVersion: scopedtransfer.ProfileVersion,
		TransferID: uuid.NewString(), OrgID: f.org, WorkspaceID: f.ws,
		SchemaVersion: scopedtransfer.SchemaVersion, MigrationSetID: scopedtransfer.MigrationSetID,
		RecipientID: uuid.NewString(), SnapshotID: uuid.NewString(),
		ClosureDigest: "sha256:" + strings.Repeat("a", 64), Tables: in.Tables,
	}
	var err error
	f.pub, f.prv, err = NewTransferRecipient()
	if err != nil {
		t.Fatal(err)
	}
	f.tc = TransferContext{
		Protocol: "keep-offline-transfer/1", Transfer: f.m.TransferID, Source: "src", Target: f.m.RecipientID,
		Snapshot: f.m.SnapshotID, Org: f.org, Workspace: f.ws,
		Schema: uint64(scopedtransfer.SchemaVersion), RecipientPub: f.pub,
	}
	f.rows = &kstore.TransferRows{}
	for _, rec := range kekRecords(t, f.org, f.src, 3) {
		f.rows.KEKs = append(f.rows.KEKs, kstore.KEKRow{
			ID: rec.ID, OrgID: rec.Org, DomainKey: "org:" + strconv.Itoa(len(rec.Domain.Org)) + ":" + rec.Domain.Org + "/user:" + strconv.Itoa(len(rec.Domain.User)) + ":" + rec.Domain.User, DomainOrg: rec.Domain.Org,
			DomainUser: rec.Domain.User, RootKeyID: rec.RootKeyID, Wrapped: rec.Wrapped, State: "active",
		})
	}
	return f
}

func TestTransferBundleRoundTrip(t *testing.T) {
	f := newBundleFixture(t)
	orig := bytes.Clone(f.rows.KEKs[0].Wrapped)
	sealed, err := BuildTransferBundle(f.pub, f.tc, f.m, f.rows, TransferRoot{f.src})
	if err != nil {
		t.Fatal("positive control failed")
	}
	if !bytes.Equal(orig, f.rows.KEKs[0].Wrapped) {
		t.Fatal("caller rows were modified")
	}
	m, rows, err := ReadTransferBundle(f.prv, f.tc, sealed, TransferRoot{f.dst})
	if err != nil || m.TransferID != f.m.TransferID || len(rows.KEKs) != 3 {
		t.Fatalf("read back failed: %v", err)
	}
	for i, k := range rows.KEKs {
		if k.ID != f.rows.KEKs[i].ID || bytes.Equal(k.Wrapped, f.rows.KEKs[i].Wrapped) {
			t.Fatal("KEK identity changed or wrapping not changed")
		}
		rec := sealer.KEKRecord{ID: k.ID, Org: k.OrgID, Wrapped: k.Wrapped, RootKeyID: k.RootKeyID, Domain: sealer.Scope{Org: k.DomainOrg, User: k.DomainUser}}
		if _, err := sealer.RewrapKEK(f.org, rec, f.dst, f.src); err != nil {
			t.Fatal("target root does not open the rewrapped KEK")
		}
		if _, err := sealer.RewrapKEK(f.org, rec, f.src, f.dst); err == nil {
			t.Fatal("source root opens the rewrapped KEK")
		}
	}
}

func TestTransferBundleRefusals(t *testing.T) {
	f := newBundleFixture(t)
	sealed, err := BuildTransferBundle(f.pub, f.tc, f.m, f.rows, TransferRoot{f.src})
	if err != nil {
		t.Fatal(err)
	}
	other := f.tc
	other.Snapshot = uuid.NewString()
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	_, otherPriv, _ := NewTransferRecipient()
	for name, c := range map[string]struct {
		prv    []byte
		tc     TransferContext
		sealed []byte
	}{
		"wrong context":   {f.prv, other, sealed},
		"wrong recipient": {otherPriv, f.tc, sealed},
		"tamper":          {f.prv, f.tc, tampered},
		"truncated":       {f.prv, f.tc, sealed[:len(sealed)/2]},
	} {
		if _, _, err := ReadTransferBundle(c.prv, c.tc, c.sealed, TransferRoot{f.dst}); !errors.Is(err, ErrTransferBundle) {
			t.Errorf("%s: want refusal, got %v", name, err)
		}
	}

	badM := f.m
	badM.OrgID = uuid.NewString()
	badRecipient := f.m
	badRecipient.RecipientID = uuid.NewString()
	badWrongRoot := f.rows.KEKs
	build := map[string]func() error{
		"manifest org differs from context": func() error {
			_, err := BuildTransferBundle(f.pub, f.tc, badM, f.rows, TransferRoot{f.src})
			return err
		},
		"manifest recipient differs from context target": func() error {
			_, err := BuildTransferBundle(f.pub, f.tc, badRecipient, f.rows, TransferRoot{f.src})
			return err
		},
		"no source root": func() error {
			_, err := BuildTransferBundle(f.pub, f.tc, f.m, f.rows, TransferRoot{})
			return err
		},
		"nil rows": func() error {
			_, err := BuildTransferBundle(f.pub, f.tc, f.m, nil, TransferRoot{f.src})
			return err
		},
		"foreign kek org": func() error {
			r := *f.rows
			r.KEKs = append([]kstore.KEKRow(nil), badWrongRoot...)
			r.KEKs[1].OrgID = uuid.NewString()
			_, err := BuildTransferBundle(f.pub, f.tc, f.m, &r, TransferRoot{f.src})
			return err
		},
		"kek domain key disagrees with its columns": func() error {
			r := *f.rows
			r.KEKs = append([]kstore.KEKRow(nil), badWrongRoot...)
			r.KEKs[0].DomainKey = "org:1:x"
			_, err := BuildTransferBundle(f.pub, f.tc, f.m, &r, TransferRoot{f.src})
			return err
		},
		"kek not under source root id": func() error {
			r := *f.rows
			r.KEKs = append([]kstore.KEKRow(nil), badWrongRoot...)
			r.KEKs[0].RootKeyID = "elsewhere"
			_, err := BuildTransferBundle(f.pub, f.tc, f.m, &r, TransferRoot{f.src})
			return err
		},
	}
	for name, run := range build {
		if err := run(); !errors.Is(err, ErrTransferBundle) {
			t.Errorf("%s: want refusal, got %v", name, err)
		}
	}
}

func TestManifestMatchesRecipient(t *testing.T) {
	f := newBundleFixture(t)
	if !manifestMatches(f.m, f.tc) {
		t.Fatal("positive control: matching manifest refused")
	}
	other := f.m
	other.RecipientID = uuid.NewString()
	if manifestMatches(other, f.tc) {
		t.Fatal("manifest naming another recipient accepted")
	}
}

func TestTransferBundleErrorsDoNotEchoInput(t *testing.T) {
	f := newBundleFixture(t)
	c := canary.New()
	f.rows.KEKs[0].OrgID = c.Value(0)
	_, err := BuildTransferBundle(f.pub, f.tc, f.m, f.rows, TransferRoot{f.src})
	if err == nil {
		t.Fatal("want refusal")
	}
	if c.In(fmt.Sprintf("%v %+v %#v", err, err, err)) {
		t.Fatal("error reflects input")
	}
}

// Sealed correctly for tc, yet the plaintext itself is malformed or describes
// another transfer: the strict decoder and the manifest binding must refuse.
func TestTransferBundleStrictDecode(t *testing.T) {
	f := newBundleFixture(t)
	seal := func(plain []byte) []byte {
		s, err := sealTransferBundle(f.pub, f.tc, plain)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	transport := bytes.Repeat([]byte{7}, 32)
	troot, err := sealer.NewLocalRootKey(transportRootID, bytes.Clone(transport))
	if err != nil {
		t.Fatal(err)
	}
	moved, err := rewrapKEKRows(f.org, f.rows.KEKs, f.src, troot)
	if err != nil {
		t.Fatal(err)
	}
	cp := *f.rows
	cp.KEKs = moved
	probe, err := f.src.Wrap(bytes.Repeat([]byte{9}, 32), []byte(rootIndependenceAAD))
	if err != nil {
		t.Fatal(err)
	}
	build := func(m scopedtransfer.Manifest, tr []byte, rows *kstore.TransferRows) []byte {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(transferBundle{Manifest: raw, Transport: tr, Probe: probe, Rows: rows})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	read := func(plain []byte) error {
		_, _, err := ReadTransferBundle(f.prv, f.tc, seal(plain), TransferRoot{f.dst})
		return err
	}
	good := build(f.m, transport, &cp)
	if err := read(good); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}
	other := f.m
	other.TransferID = uuid.NewString()
	otherWS := f.m
	otherWS.WorkspaceID = uuid.NewString()
	wrongTransport := bytes.Repeat([]byte{8}, 32)
	for name, plain := range map[string][]byte{
		"trailing value":      append(bytes.Clone(good), '{', '}'),
		"unknown field":       bytes.Replace(good, []byte(`{"manifest"`), []byte(`{"extra":1,"manifest"`), 1),
		"missing rows":        build(f.m, transport, nil),
		"manifest other xfer": build(other, transport, &cp),
		"manifest other ws":   build(otherWS, transport, &cp),
		"short transport":     build(f.m, transport[:16], &cp),
		"no transport":        build(f.m, nil, &cp),
		"wrong transport":     build(f.m, wrongTransport, &cp),
		"not json":            []byte(`x`),
	} {
		if err := read(plain); !errors.Is(err, ErrTransferBundle) {
			t.Errorf("%s: want refusal, got %v", name, err)
		}
	}
	if _, err := BuildTransferBundle(f.pub, f.tc, other, f.rows, TransferRoot{f.src}); !errors.Is(err, ErrTransferBundle) {
		t.Error("build accepted a manifest of another transfer")
	}
}

// The target must be independent of the SOURCE root, not merely of the
// one-shot transport root: each hop alone passes when the source key material
// is reused as the target, so the bundle itself must let the target prove it.
func TestTransferBundleRejectsSourceRootAsTarget(t *testing.T) {
	f := newBundleFixture(t)
	defer clear(f.prv)
	sealed, err := BuildTransferBundle(f.pub, f.tc, f.m, f.rows, TransferRoot{f.src})
	if err != nil {
		t.Fatal("positive control: export failed")
	}
	if _, rows, err := ReadTransferBundle(f.prv, f.tc, sealed, TransferRoot{f.dst}); err != nil || len(rows.KEKs) != 3 {
		t.Fatal("positive control: an independent target root was rejected")
	}
	if _, rows, err := ReadTransferBundle(f.prv, f.tc, sealed, TransferRoot{f.src}); !errors.Is(err, ErrTransferBundle) {
		t.Fatalf("source root accepted as target; rewrapped KEKs=%d", len(rows.KEKs))
	}
}

// The same key material under another id is still the source root.
func TestTransferBundleRejectsSameMaterialUnderAnotherID(t *testing.T) {
	f := newBundleFixture(t)
	defer clear(f.prv)
	srcRoot, key := newRoot(t, "root")
	defer clear(key)
	rows := &kstore.TransferRows{}
	for _, rec := range kekRecords(t, f.org, srcRoot, 3) {
		rows.KEKs = append(rows.KEKs, kstore.KEKRow{
			ID: rec.ID, OrgID: rec.Org, DomainKey: "org:" + strconv.Itoa(len(rec.Domain.Org)) + ":" + rec.Domain.Org + "/user:" + strconv.Itoa(len(rec.Domain.User)) + ":" + rec.Domain.User, DomainOrg: rec.Domain.Org,
			DomainUser: rec.Domain.User, RootKeyID: rec.RootKeyID, Wrapped: rec.Wrapped, State: "active",
		})
	}
	sealed, err := BuildTransferBundle(f.pub, f.tc, f.m, rows, TransferRoot{srcRoot})
	if err != nil {
		t.Fatal("positive control: export failed")
	}
	twin, err := sealer.NewLocalRootKey("another-id", bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadTransferBundle(f.prv, f.tc, sealed, TransferRoot{twin}); !errors.Is(err, ErrTransferBundle) {
		t.Fatal("the source key material under another id was accepted as the target")
	}
}

// A bundle without the independence probe (an older or hand-made layout) is
// refused: the importer cannot prove independence from it.
func TestTransferBundleWithoutProbeIsRefused(t *testing.T) {
	f := newBundleFixture(t)
	defer clear(f.prv)
	sealed, err := buildTransferBundleNoProbe(f.pub, f.tc, f.m, f.rows, TransferRoot{f.src})
	if err != nil {
		t.Fatal("positive control: building the probe-less layout failed")
	}
	if _, _, err := ReadTransferBundle(f.prv, f.tc, sealed, TransferRoot{f.dst}); !errors.Is(err, ErrTransferBundle) {
		t.Fatalf("a bundle without a probe was accepted: %v", err)
	}
}
