package builtin

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestOpenTransferRoot(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, content []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, mode); err != nil { //nolint:gosec // G306: the mode is the thing under test
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { //nolint:gosec // G302: the mode is the thing under test
			t.Fatal(err)
		}
		return p
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	good := write("good", []byte(enc), 0o600)
	r, err := OpenTransferRoot(good, "root-a")
	if err != nil || r.k == nil || r.k.ID() != "root-a" {
		t.Fatalf("positive control failed: %v", err)
	}
	c := canary.Of(enc)
	shown := fmt.Sprintf("%v %+v %#v %s", r, r, r, r)
	if c.In(shown) || strings.Contains(shown, "root-a") {
		t.Fatal("handle formatting exposes the root")
	}
	short := write("short", []byte(base64.StdEncoding.EncodeToString(raw[:16])), 0o600)
	zero := write("zero", []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), 0o600)
	open := write("open", []byte(enc), 0o644)
	for name, in := range map[string]struct{ path, id string }{
		"empty path": {"", "root-a"}, "empty id": {good, ""}, "missing": {filepath.Join(dir, "none"), "root-a"},
		"short": {short, "root-a"}, "all zero": {zero, "root-a"}, "world readable": {open, "root-a"},
	} {
		_, err := OpenTransferRoot(in.path, in.id)
		if err == nil {
			t.Errorf("%s: want refusal", name)
		} else if c.In(err.Error()) {
			t.Errorf("%s: error reflects the root", name)
		}
	}
}
