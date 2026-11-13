package app

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func exportArgs(d string, over map[string]string) []string {
	m := map[string]string{
		"--org": someUID, "--workspace": someUID, "--transfer": someUID, "--source": someUID,
		"--target": someUID, "--snapshot": someUID, "--schema": "50",
		"--recipient-public-file": filepath.Join(d, "r.pub"), "--expect-recipient-fingerprint": pinHex,
		"--bundle": filepath.Join(d, "out.sealed"), "--checkpoint": filepath.Join(d, "out.checkpoint"),
	}
	for k, v := range over {
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	var out []string
	for k, v := range m {
		out = append(out, k, v)
	}
	return out
}

func TestTransferExportUsageAndStaticRefusals(t *testing.T) {
	d := carrierDir(t)
	c := canary.New()
	t.Setenv("KEEP_DATABASE_URL", "host=127.0.0.1 port=1 password="+c.Value(0))
	t.Setenv("KEEP_ROOT_KEY_FILE", filepath.Join(d, "root-"+c.Value(0)))
	for _, miss := range []string{"--org", "--workspace", "--transfer", "--source", "--target", "--snapshot", "--schema", "--recipient-public-file", "--expect-recipient-fingerprint", "--bundle", "--checkpoint"} {
		code, _, errs := runTransfer(append([]string{"export"}, exportArgs(d, map[string]string{miss: ""})...)...)
		if code != 2 || !strings.Contains(errs, "usage") {
			t.Fatalf("missing %s: %d %q", miss, code, errs)
		}
	}
	pub := []byte("public-carrier-bytes")
	if err := os.WriteFile(filepath.Join(d, "r.pub"), pub, 0o600); err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(pub)
	good := hex.EncodeToString(fp[:])
	for name, tc := range map[string]struct {
		over   map[string]string
		reason string
	}{
		"bad pin":         {map[string]string{"--expect-recipient-fingerprint": "zz"}, "pin"},
		"bad identity":    {map[string]string{"--snapshot": "nope"}, "identity"},
		"upper identity":  {map[string]string{"--snapshot": strings.ToUpper(someUID)}, "identity"},
		"wrong recipient": {nil, "recipient"},
		"root unusable":   {map[string]string{"--expect-recipient-fingerprint": good}, "root"},
	} {
		code, out, errs := runTransfer(append([]string{"export"}, exportArgs(d, tc.over)...)...)
		if code == 0 || !strings.Contains(errs, "reason="+tc.reason) || c.In(out) || c.In(errs) {
			t.Fatalf("%s: %d %q", name, code, errs)
		}
	}
	for _, n := range []string{"out.sealed", "out.checkpoint"} {
		if _, err := os.Stat(filepath.Join(d, n)); err == nil {
			t.Fatalf("a refused export left %s", n)
		}
	}
}

func TestTransferFinalizeUsageAndStaticRefusals(t *testing.T) {
	d := carrierDir(t)
	c := canary.New()
	t.Setenv("KEEP_DATABASE_URL", "host=127.0.0.1 port=1 password="+c.Value(0))
	args := func(over map[string]string) []string {
		m := map[string]string{"--org": someUID, "--checkpoint": filepath.Join(d, "cp"), "--approval": filepath.Join(d, "ap"), "--quiescence-confirmed": "true"}
		for k, v := range over {
			if v == "" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		var o []string
		for k, v := range m {
			o = append(o, k, v)
		}
		return o
	}
	for _, miss := range []string{"--org", "--checkpoint", "--approval", "--quiescence-confirmed"} {
		code, _, errs := runTransfer(append([]string{"finalize"}, args(map[string]string{miss: ""})...)...)
		if code != 2 || !strings.Contains(errs, "usage") {
			t.Fatalf("missing %s: %d %q", miss, code, errs)
		}
	}
	if code, _, errs := runTransfer(append([]string{"finalize"}, args(map[string]string{"--org": strings.ToUpper(someUID)})...)...); code == 0 || !strings.Contains(errs, "reason=identity") {
		t.Fatalf("a non-canonical org id must be refused as an identity: %d %q", code, errs)
	}
	code, out, errs := runTransfer(append([]string{"finalize"}, args(map[string]string{"--quiescence-confirmed": "false"})...)...)
	if code == 0 || !strings.Contains(errs, "reason=quiescence") || c.In(out+errs) {
		t.Fatalf("no freeze assertion must refuse: %d %q", code, errs)
	}
	if err := os.WriteFile(filepath.Join(d, "cp"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runTransfer(append([]string{"finalize"}, args(nil)...)...)
	if code == 0 || !strings.Contains(errs, "reason=checkpoint") || c.In(out+errs) {
		t.Fatalf("bad checkpoint: %d %q", code, errs)
	}
	if _, err := os.Stat(filepath.Join(d, "ap")); err == nil {
		t.Fatal("a refused finalize wrote an approval")
	}
}
