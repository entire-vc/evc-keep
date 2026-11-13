package audit

// StoredRecord is one audit row as stored: the record with its prev_hash, the
// stored org_seq and the stored hash. Times must already be UTC, as Verify
// normalises them before recomputing a hash.
type StoredRecord struct {
	Record Record
	Seq    int64
	Hash   string
}

// StoredHead is the audit_chain_heads row of an organization, if any.
type StoredHead struct {
	Present  bool
	Position int64
	Hash     string
}

// VerifyRows walks an organization's chain held in memory with the same four
// checks and the same order as [Verify]: sequence, hash recomputed from the
// stored fields, link to the previous hash, and finally the head. Records must
// be in org_seq order. It exists so a chain can be verified before it is
// written anywhere, for example in an offline transfer; the two verifiers are
// kept in agreement by a test that feeds both the same chains.
func VerifyRows(orgID string, recs []StoredRecord, head StoredHead) (VerifyResult, error) {
	expectedPrev := GenesisHash
	var walked int64
	for _, s := range recs {
		rec := s.Record
		walked++
		if rec.OrgID != orgID {
			return VerifyResult{Checked: walked, BrokenID: safeRecordID(rec.ID), BrokenPosition: s.Seq, BreakKind: BreakSequence}, nil
		}
		recomputed, err := computeHash(rec.PrevHash, rec)
		if err != nil {
			return VerifyResult{}, err
		}
		broken := func(kind BreakKind) (VerifyResult, error) {
			return VerifyResult{Checked: walked, BrokenID: safeRecordID(rec.ID), BrokenPosition: s.Seq, BreakKind: kind}, nil
		}
		if s.Seq != walked {
			return broken(BreakSequence)
		}
		if recomputed != s.Hash {
			return broken(BreakHash)
		}
		if rec.PrevHash != expectedPrev {
			return broken(BreakLink)
		}
		expectedPrev = s.Hash
	}
	if !head.Present {
		if walked > 0 {
			return VerifyResult{Checked: walked, BrokenPosition: walked, BreakKind: BreakHead}, nil
		}
		return VerifyResult{OK: true}, nil
	}
	if head.Position != walked || head.Hash != expectedPrev {
		return VerifyResult{Checked: walked, BrokenPosition: head.Position, BreakKind: BreakHead}, nil
	}
	return VerifyResult{OK: true, Checked: walked}, nil
}
