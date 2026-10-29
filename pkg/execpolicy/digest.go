package execpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
)

// Digest identifies an approved template: lowercase hex SHA-256 over a
// length-prefixed encoding of every field. The server signs this digest into
// a job and the runner compares it with its own copy, so a template edited on
// either side after approval no longer runs. Length prefixes keep
// ["a","bc"] and ["ab","c"] apart; params are sorted by name, so the digest
// does not depend on map order.
func Digest(t Template) string {
	h := sha256.New()
	str := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	num := func(n int) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n)) //nolint:gosec // G115: n is a length, never negative
		h.Write(b[:])
	}
	str("keep-exec-template-v1")
	num(len(t.Argv))
	for _, a := range t.Argv {
		str(a)
	}
	names := make([]string, 0, len(t.Params))
	for n := range t.Params {
		names = append(names, n)
	}
	sort.Strings(names)
	num(len(names))
	for _, n := range names {
		str(n)
		str(t.Params[n].Pattern)
	}
	num(len(t.SecretEnv))
	for _, e := range t.SecretEnv {
		str(e)
	}
	num(int(t.Network.Mode))
	num(len(t.Network.Destinations))
	for _, d := range t.Network.Destinations {
		str(d.Host)
		num(d.Port)
	}
	return hex.EncodeToString(h.Sum(nil))
}
