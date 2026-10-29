package enrolltoken

import "testing"

func TestHostAttrsRequireUIDAndClosedLabels(t *testing.T) {
	f := false
	valid := HostAttrs{UIDShared: &f, Labels: map[string]string{"environment": "staging", "platform": "linux"}}
	if err := valid.Validate(); err != nil {
		t.Fatal("valid host attributes rejected")
	}
	for _, attrs := range []HostAttrs{
		{Labels: map[string]string{}},
		{UIDShared: &f, Labels: map[string]string{"environment": "unknown"}},
		{UIDShared: &f, Labels: map[string]string{"platform": "windows"}},
		{UIDShared: &f, Labels: map[string]string{"role": "production"}},
	} {
		if err := attrs.Validate(); err == nil {
			t.Fatal("invalid host attributes accepted")
		}
	}
	if err := (HostAttrs{UIDShared: &f, Labels: map[string]string{}}).Validate(); err != nil {
		t.Fatal("empty labels should be valid")
	}
}
