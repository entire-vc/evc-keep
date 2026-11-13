package builtin

import (
	"bytes"
	"crypto/rand"
	"encoding/json"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	kstore "github.com/entire-vc/evc-keep/internal/store"
)

// buildTransferBundleNoProbe is BuildTransferBundle's layout without the
// probe field, for the refusal test.
func buildTransferBundleNoProbe(pub []byte, tc TransferContext, m scopedtransfer.Manifest, rows *kstore.TransferRows, source TransferRoot) ([]byte, error) {
	transport := make([]byte, 32)
	defer clear(transport)
	if _, err := rand.Read(transport); err != nil {
		return nil, err
	}
	troot, err := sealer.NewLocalRootKey(transportRootID, bytes.Clone(transport))
	if err != nil {
		return nil, err
	}
	moved, err := rewrapKEKRows(m.OrgID, rows.KEKs, source.k, troot)
	if err != nil {
		return nil, err
	}
	cp := *rows
	cp.KEKs = moved
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(struct {
		Manifest  json.RawMessage      `json:"manifest"`
		Transport []byte               `json:"transport"`
		Rows      *kstore.TransferRows `json:"rows"`
	}{raw, transport, &cp})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return sealTransferBundle(pub, tc, plain)
}
