// Canonical JSON and hash-chain format, R-AUD-1 (threat model §4.2)
// ===================================================================
//
// Canonical JSON
// ---------------
// canonicalJSON (canonicaljson.go) renders a Record as: object keys sorted
// lexically (byte order) at every nesting level, no insignificant
// whitespace anywhere — no spaces after ':' or ',', no trailing newline.
// Arrays keep their original element order (Record has none today, but the
// rule is stated for completeness). Numbers render exactly as
// encoding/json's decoder read them (via json.Decoder.UseNumber, so an int
// field round-trips as the same digit string, never reformatted through a
// float64). Strings use encoding/json's own escaping.
//
// This is the same shape as JCS (RFC 8785) restricted to the subset of JSON
// Record ever produces (objects, strings, numbers, bools, no floats in
// practice) — named and implemented locally rather than pulling in an RFC
// 8785 library, because the subset is small and the property that matters
// operationally is narrower than full JCS compliance: two Go processes
// running this package's own code must always canonicalize the same Record
// value identically. That property is what TestCanonicalJSONIsDeterministic
// and TestCanonicalJSONKeysAreSorted check, not conformance to the RFC.
//
// Hash chain
// ----------
// Every organization has its own chain, independent of every other
// organization's. For a record at position n (1-indexed) in org O:
//
//	hash[n] = SHA-256(prev_hash[n] || canonical_json(record[n]))
//
// where record[n].PrevHash == prev_hash[n] == hash[n-1], and hash[0] (the
// value fed as prev_hash to the first record) is [GenesisHash], a fixed
// all-zero value rather than the output of any hash computation — an
// organization's chain always starts from the same known point, so
// verification never needs a special case for "this is the first record".
//
// The two operands are concatenated as raw bytes with no separator: prevHash
// is always a fixed-length, 64-character lowercase-hex string (a SHA-256
// digest's hex encoding, or [GenesisHash] in that same shape) and canonical
// JSON's own first byte is always '{', which cannot appear inside a hex
// string — so the boundary between the two parts is unambiguous without a
// separator, and no valid prevHash value could accidentally produce a byte
// sequence indistinguishable from the start of the JSON that follows.
//
// GenesisHash is chosen in the same 64-hex-character shape a real digest
// takes, deliberately — it is a value verify.go and journal.go can treat
// exactly like any other prev_hash, with no special-cased length check
// anywhere. It is not itself the output of SHA-256 (an actual all-zero
// SHA-256 digest is cryptographically negligible to produce, but not
// impossible even in principle) — it is a fixed sentinel every
// organization's chain starts from, and treated purely as an opaque
// previous-value, never re-derived or checked against anything.
//
// Ordering and concurrency
// -------------------------
// Within one organization, record order is the order in which Append's
// callers win the row lock on that organization's row in audit_chain_heads:
// Append upserts the row (`INSERT … ON CONFLICT (org_id) DO UPDATE`, which
// takes the row lock even on a first insert) and holds the lock for the
// whole transaction that reads the current head, inserts the new record and
// advances the head. Order is never the order Append was called by the
// process's own goroutines, and never wall-clock time (two records can share
// the same millisecond). Two organizations append fully in parallel (they
// lock different rows); two Appends racing within one organization are
// strictly ordered by whichever transaction acquires the lock first — see
// journal.go and TestAppend_ConcurrentAcrossOrgsKeepsBothChainsIntact, whose
// Verify over 500 records per organization is what proves the ordering (the
// race detector cannot see locks taken inside the database).
//
// Verification
// ------------
// Verify (verify.go) reads an organization's records in that same order
// (audit_records.org_seq, assigned from the locked head row) inside one
// read-only snapshot and checks, per record: org_seq runs 1, 2, 3, … without
// a gap (BreakSequence); the stored hash equals the hash recomputed from the
// record's own stored fields and stored prev_hash (BreakHash — a record
// edited in place); and prev_hash equals the previous record's hash, with
// the first record starting at GenesisHash (BreakLink — a record deleted
// from the middle, or from the front). After the walk it checks that the
// chain ends at the position and hash audit_chain_heads records
// (BreakHead — records cut off the end, or a whole organization wiped).
// The first failure is reported by kind, id and position; see verify.go and
// verify_test.go.
//
// What the chain does not prove
// -----------------------------
// The hash is unkeyed and its formula is public, and audit_chain_heads
// lives in the same database. Anyone who can write both tables — the
// database superuser, or a compromised application role that has INSERT on
// audit_records and UPDATE on the head — can rewrite a suffix of the chain,
// recompute every hash and the head, and Verify will report OK. Likewise a
// direct INSERT of a forged last record by such a writer verifies. The
// chain therefore detects accidental damage and tampering by a writer who
// does not also forge the chain; it is not an integrity guarantee against
// the party who runs the database. Closing that gap needs a key or an
// anchor outside the database (a MAC or signature over the head, or a head
// published elsewhere) and is a threat-model decision, not something this
// package can settle alone.
package audit
