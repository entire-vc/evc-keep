package audit

import (
	"crypto/sha256"
	"encoding/hex"
)

// GenesisHash is the fixed prev_hash value for the first record ever
// appended to an organization's chain — see doc.go. It is not the output of
// any hash computation; it exists only so [computeHash]'s formula never
// needs a special case for "there is no previous record". It is 64
// lowercase hex characters, the same shape a real SHA-256 digest takes.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// computeHash implements the threat model's §4.2 formula:
//
//	hash = SHA-256(prev_hash || canonical_json(record))
//
// prev_hash is concatenated as its own raw bytes (the hex string, not
// decoded), immediately followed by r's canonical JSON — see doc.go for why
// concatenation must be unambiguous between the two parts, and why that
// rules out simpler alternatives. r.PrevHash must already equal prevHash
// (the caller sets it before calling this) — computeHash does not set it
// itself, so the value that gets hashed is exactly the value that gets
// stored.
func computeHash(prevHash string, r Record) (string, error) {
	body, err := canonicalJSON(r)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}
