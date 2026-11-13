package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
)

// CopiedCounts must name exactly the tables the registry copies, no more and
// no fewer: a table missing here would be imported without a count check.
func TestCopiedCountsMatchRegistry(t *testing.T) {
	got := (&TransferRows{}).CopiedCounts()
	want := map[string]bool{}
	for _, p := range scopedtransfer.TablePolicies() {
		if p.Disposition == scopedtransfer.CopyRows || p.Disposition == scopedtransfer.RewrapRows {
			want[p.Name] = true
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("copied table %s has no count", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("count for %s, which the registry does not copy", name)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d counts, registry copies %d", len(got), len(want))
	}
}
