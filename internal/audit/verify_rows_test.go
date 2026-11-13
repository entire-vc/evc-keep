package audit

import (
	"testing"
	"time"
)

// memChain builds an honest in-memory chain of n records for org.
func memChain(t *testing.T, org string, n int) ([]StoredRecord, StoredHead) {
	t.Helper()
	var recs []StoredRecord
	prev := GenesisHash
	for i := 1; i <= n; i++ {
		r := newRecord(org, nil)
		r.ID = "01J8ZZZZZZZZZZZZZZZZZZZZ" + string(rune('A'+i/10)) + string(rune('A'+i%10))
		r.TS = time.Date(2026, 11, 3, 12, 0, i, 0, time.UTC)
		r.PrevHash = prev
		h, err := computeHash(prev, r)
		if err != nil {
			t.Fatal("hash")
		}
		recs = append(recs, StoredRecord{Record: r, Seq: int64(i), Hash: h})
		prev = h
	}
	return recs, StoredHead{Present: n > 0, Position: int64(n), Hash: prev}
}

func TestVerifyRows(t *testing.T) {
	const org = "org-mem"
	cases := map[string]struct {
		mutate func(recs []StoredRecord, head *StoredHead) []StoredRecord
		kind   BreakKind
	}{
		"honest":   {func(r []StoredRecord, h *StoredHead) []StoredRecord { return r }, ""},
		"tamper":   {func(r []StoredRecord, h *StoredHead) []StoredRecord { r[1].Record.Actor.ID = "x"; return r }, BreakHash},
		"gap":      {func(r []StoredRecord, h *StoredHead) []StoredRecord { r[2].Seq = 4; return r }, BreakSequence},
		"deleted":  {func(r []StoredRecord, h *StoredHead) []StoredRecord { return append(r[:1], r[2:]...) }, BreakSequence},
		"relinked": {func(r []StoredRecord, h *StoredHead) []StoredRecord { r[2].Record.PrevHash = GenesisHash; return r }, BreakHash},
		"forged link": {func(r []StoredRecord, h *StoredHead) []StoredRecord {
			// A self-consistent record whose prev_hash points elsewhere: only the
			// link check can catch it.
			r[2].Record.PrevHash = GenesisHash
			r[2].Hash, _ = computeHash(GenesisHash, r[2].Record)
			h.Hash = r[2].Hash
			return r
		}, BreakLink},
		"not genesis":  {func(r []StoredRecord, h *StoredHead) []StoredRecord { return r[1:] }, BreakSequence},
		"head missing": {func(r []StoredRecord, h *StoredHead) []StoredRecord { *h = StoredHead{}; return r }, BreakHead},
		"head stale":   {func(r []StoredRecord, h *StoredHead) []StoredRecord { h.Position--; return r }, BreakHead},
		"head hash":    {func(r []StoredRecord, h *StoredHead) []StoredRecord { h.Hash = GenesisHash; return r }, BreakHead},
		"foreign org":  {func(r []StoredRecord, h *StoredHead) []StoredRecord { r[1].Record.OrgID = "other"; return r }, BreakSequence},
		"truncated": {func(r []StoredRecord, h *StoredHead) []StoredRecord {
			return r[:2]
		}, BreakHead},
	}
	for name, c := range cases {
		recs, head := memChain(t, org, 3)
		res, err := VerifyRows(org, c.mutate(recs, &head), head)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.kind == "" {
			if !res.OK || res.Checked != 3 {
				t.Fatalf("%s: honest chain rejected: %+v", name, res)
			}
			continue
		}
		if res.OK || res.BreakKind != c.kind {
			t.Fatalf("%s: want %s, got %+v", name, c.kind, res)
		}
	}
	if res, _ := VerifyRows(org, nil, StoredHead{}); !res.OK || res.Checked != 0 {
		t.Fatal("empty organization rejected")
	}
}
