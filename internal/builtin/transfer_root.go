package builtin

import (
	"crypto/subtle"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
)

// TransferRoot is an opened root key for one offline-transfer operation. It
// is opaque: key bytes never leave the zone and the value formats as nothing
// useful. The zero value is not usable.
type TransferRoot struct{ k sealer.RootKey }

// OpenTransferRoot reads a persistent local root (the same file format as
// KEEP_ROOT_KEY_FILE) under the given key id. Only the opened handle leaves.
func OpenTransferRoot(path, keyID string) (TransferRoot, error) {
	if path == "" || keyID == "" {
		return TransferRoot{}, errLocalKey
	}
	encoded, err := readLocalRoot(path)
	if err != nil {
		return TransferRoot{}, errLocalKey
	}
	var root sealer.RootKey
	key := make([]byte, max(32, len(encoded)))
	defer clear(key)
	_, err = openLocalEncoded(encoded, key, func(raw []byte) (*Local, error) {
		defer clear(raw)
		if len(raw) != 32 || subtle.ConstantTimeCompare(raw, make([]byte, 32)) == 1 {
			return nil, errLocalKey
		}
		r, err := sealer.NewLocalRootKey(keyID, raw)
		if err != nil {
			return nil, errLocalKey
		}
		root = r
		return &Local{}, nil
	})
	if err != nil {
		return TransferRoot{}, errLocalKey
	}
	return TransferRoot{k: root}, nil
}

// String and GoString keep the handle out of logs and receipts.
func (TransferRoot) String() string   { return "[transfer root]" }
func (TransferRoot) GoString() string { return "[transfer root]" }
