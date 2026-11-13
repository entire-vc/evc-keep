package builtin

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	kstore "github.com/entire-vc/evc-keep/internal/store"
)

// ErrTransferBundle is the only error bundle building and reading return. It
// carries no row value, key, context or library text.
var ErrTransferBundle = errors.New("builtin: offline transfer bundle rejected")

// transportRootID names the one-shot root that carries the KEK closure
// between the two installations. It exists only inside one sealed bundle.
const transportRootID = "offline-transfer-transport-v1"

// transferBundle is the closed plaintext layout inside the HPKE seal: the
// canonical manifest, the typed rows and the one-shot transport root that
// wraps the KEK rows. Value rows are ciphertext envelopes; no plaintext
// secret value is part of it. The source never sees the target root: the
// target rewraps from the transport root to its own root on import.
type transferBundle struct {
	Manifest  json.RawMessage      `json:"manifest"`
	Transport []byte               `json:"transport"`
	Probe     []byte               `json:"probe"`
	Rows      *kstore.TransferRows `json:"rows"`
}

// BuildTransferBundle rewraps the KEK closure of rows from the source root to
// a fresh one-shot transport root, then seals manifest, transport root and
// rows to recipientPub under tc. rows is not modified. The manifest must
// describe exactly this transfer.
func BuildTransferBundle(recipientPub []byte, tc TransferContext, m scopedtransfer.Manifest, rows *kstore.TransferRows, source TransferRoot) ([]byte, error) {
	if rows == nil || source.k == nil || !manifestMatches(m, tc) {
		return nil, ErrTransferBundle
	}
	transport := make([]byte, 32)
	defer clear(transport)
	if _, err := rand.Read(transport); err != nil {
		return nil, ErrTransferBundle
	}
	tclone := bytes.Clone(transport)
	defer clear(tclone)
	troot, err := sealer.NewLocalRootKey(transportRootID, tclone)
	if err != nil {
		return nil, ErrTransferBundle
	}
	moved, err := rewrapKEKRows(m.OrgID, rows.KEKs, source.k, troot)
	if err != nil {
		return nil, ErrTransferBundle
	}
	// A random probe wrapped by the SOURCE root travels inside the seal so the
	// target can prove its own root is not the source key material: the two
	// rewrap hops each compare only against the one-shot transport root.
	probe := make([]byte, 32)
	defer clear(probe)
	if _, err := rand.Read(probe); err != nil {
		return nil, ErrTransferBundle
	}
	wrappedProbe, err := source.k.Wrap(probe, []byte(rootIndependenceAAD))
	if err != nil {
		return nil, ErrTransferBundle
	}
	cp := *rows
	cp.KEKs = moved
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, ErrTransferBundle
	}
	plain, err := json.Marshal(transferBundle{Manifest: raw, Transport: transport, Probe: wrappedProbe, Rows: &cp})
	if err != nil {
		return nil, ErrTransferBundle
	}
	defer clear(plain)
	sealed, err := sealTransferBundle(recipientPub, tc, plain)
	if err != nil {
		return nil, ErrTransferBundle
	}
	return sealed, nil
}

// ReadTransferBundle opens sealed with recipientPriv under tc and decodes it
// strictly: unknown fields, trailing data and a manifest that is not the
// canonical encoding or does not match tc are refused. The KEK rows are then
// moved from the transport root to target, so the returned rows are wrapped
// by the target's own root. It performs no semantic closure check; that is
// the caller's next step.
func ReadTransferBundle(recipientPriv []byte, tc TransferContext, sealed []byte, target TransferRoot) (scopedtransfer.Manifest, *kstore.TransferRows, error) {
	if target.k == nil {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	plain, err := openTransferBundle(recipientPriv, tc, sealed)
	if err != nil {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	defer clear(plain)
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	var b transferBundle
	err = dec.Decode(&b)
	defer clear(b.Transport)
	if err != nil || b.Rows == nil {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	m, err := scopedtransfer.ParseManifest(b.Manifest)
	if err != nil || !manifestMatches(m, tc) {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	// The target must not be the source's key material, under any id: a
	// bundle with no probe cannot prove it, and a probe the target opens
	// proves it is the same key.
	if len(b.Probe) == 0 || opensProbe(target.k, b.Probe) {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	tclone := bytes.Clone(b.Transport)
	defer clear(tclone)
	troot, err := sealer.NewLocalRootKey(transportRootID, tclone)
	if err != nil {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	moved, err := rewrapKEKRows(m.OrgID, b.Rows.KEKs, troot, target.k)
	if err != nil {
		return scopedtransfer.Manifest{}, nil, ErrTransferBundle
	}
	b.Rows.KEKs = moved
	return m, b.Rows, nil
}

func manifestMatches(m scopedtransfer.Manifest, tc TransferContext) bool {
	return m.TransferID == tc.Transfer && m.SnapshotID == tc.Snapshot &&
		m.OrgID == tc.Org && m.WorkspaceID == tc.Workspace && m.RecipientID == tc.Target &&
		m.SchemaVersion > 0 && strconv.FormatInt(m.SchemaVersion, 10) == strconv.FormatUint(tc.Schema, 10) &&
		m.Version == scopedtransfer.ManifestVersion
}

// rewrapKEKRows moves every KEK row from source to target, keeping ID,
// organisation, domain and state. The result is a new slice.
func rewrapKEKRows(org string, in []kstore.KEKRow, source, target sealer.RootKey) ([]kstore.KEKRow, error) {
	recs := make([]sealer.KEKRecord, len(in))
	for i, r := range in {
		if r.OrgID != org || r.RootKeyID != source.ID() {
			return nil, ErrTransferBundle
		}
		sc, ok := kekScope(r)
		if !ok {
			return nil, ErrTransferBundle
		}
		recs[i] = sealer.KEKRecord{
			ID: r.ID, Org: r.OrgID, RootKeyID: r.RootKeyID, Wrapped: r.Wrapped, Domain: sc,
		}
	}
	moved, err := rewrapKEKsForTransfer(org, recs, source, target)
	if err != nil || len(moved) != len(in) {
		return nil, ErrTransferBundle
	}
	out := make([]kstore.KEKRow, len(in))
	for i, r := range in {
		r.Wrapped = moved[i].Wrapped
		r.RootKeyID = moved[i].RootKeyID
		out[i] = r
	}
	return out, nil
}
