package transferverify

import (
	"strings"
	"testing"
)

func TestClosureDigestIgnoresOnlyKEKWrapping(t *testing.T) {
	rows, _ := seededRows(t)
	base, err := ClosureDigest(rows)
	if err != nil || !strings.HasPrefix(base, "sha256:") || len(base) != 71 {
		t.Fatalf("digest %q %v", base, err)
	}
	again, _ := ClosureDigest(rows)
	if again != base {
		t.Fatal("not deterministic")
	}
	if len(rows.KEKs) == 0 {
		t.Fatal("fixture has no KEK rows")
	}
	rows.KEKs[0].Wrapped = []byte("other")
	rows.KEKs[0].RootKeyID = "other-root"
	if d, _ := ClosureDigest(rows); d != base {
		t.Fatal("KEK wrapping must not change the digest")
	}
	rows.KEKs[0].State = "retired"
	if d, _ := ClosureDigest(rows); d == base {
		t.Fatal("KEK state change not covered")
	}
	rows.KEKs[0].State = "active"
	rows.Users[0].Email = "x@example.invalid"
	if d, _ := ClosureDigest(rows); d == base {
		t.Fatal("row change not covered")
	}
	if _, err := ClosureDigest(nil); err == nil {
		t.Fatal("nil rows accepted")
	}
}
