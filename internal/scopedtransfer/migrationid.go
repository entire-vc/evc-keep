package scopedtransfer

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/fs"
	"sort"
)

// MigrationSetIDOf computes the pin documented at [MigrationSetID] from a
// migration directory. A reader uses it on the embedded migrations it was
// built with; it proves source identity, not the state of any database.
func MigrationSetIDOf(fsys fs.FS, dir string) (string, error) {
	paths, err := fs.Glob(fsys, dir+"/*.sql")
	if err != nil || len(paths) == 0 {
		return "", ErrProfile
	}
	sort.Strings(paths)
	h := sha256.New()
	_, _ = h.Write([]byte("keep-scoped-transfer-migrations-v1\x00"))
	for _, p := range paths {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return "", ErrProfile
		}
		name := p[len(dir)+1:]
		for _, part := range [][]byte{[]byte(name), raw} {
			var size [8]byte
			binary.BigEndian.PutUint64(size[:], uint64(len(part)))
			_, _ = h.Write(size[:])
			_, _ = h.Write(part)
		}
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
