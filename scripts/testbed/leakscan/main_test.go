package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testValue = "Zk3-test-needle-0123456789abcdefXYZ"

func scan(t *testing.T, needles map[string]string, text string, extra ...string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	for name, v := range needles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := filepath.Join(t.TempDir(), "text")
	if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	args := append(append([]string{"-needles", dir}, extra...), "t="+f)
	rc := run(args, strings.NewReader(""), &out, &errb)
	return rc, out.String() + errb.String()
}

func TestCleanTextPasses(t *testing.T) {
	if rc, out := scan(t, map[string]string{"v": testValue}, "nothing here"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, out)
	}
}

func TestPlainAndShiftedBase64AreCaught(t *testing.T) {
	for _, text := range []string{
		"x " + testValue,
		base64.StdEncoding.EncodeToString([]byte("a" + testValue)),
		base64.StdEncoding.EncodeToString([]byte("ab" + testValue)),
	} {
		if rc, _ := scan(t, map[string]string{"v": testValue}, text); rc != 1 {
			t.Fatalf("a leak went unseen: %.20q", text)
		}
	}
}

// An empty or short needle must stop the scan, not be skipped: skipping it is
// how a scan reports clean while not looking for a value.
func TestEmptyOrShortNeedleStopsTheScan(t *testing.T) {
	for name, needles := range map[string]map[string]string{
		"empty": {"v": testValue, "carrier": ""},
		"short": {"v": testValue, "carrier": "tooshort"},
		"only":  {"carrier": ""},
	} {
		if rc, out := scan(t, needles, "anything"); rc != 2 {
			t.Fatalf("%s: rc=%d, want 2: %s", name, rc, out)
		}
	}
}

func TestNoNeedlesStopsTheScan(t *testing.T) {
	if rc, _ := scan(t, nil, "anything"); rc != 2 {
		t.Fatalf("rc=%d, want 2", rc)
	}
}

func TestControlPassesOnARealNeedle(t *testing.T) {
	if rc, out := scan(t, map[string]string{"v": testValue}, "clean", "-control"); rc != 0 || !strings.Contains(out, "control ok") {
		t.Fatalf("rc=%d %s", rc, out)
	}
}

// A scanner that cannot see its own needles must fail the control before it
// reports anything: a control that cannot fail proves nothing.
func TestControlStopsABlindScanner(t *testing.T) {
	orig := sees
	sees = func(needle, string) bool { return false }
	defer func() { sees = orig }()
	rc, out := scan(t, map[string]string{"v": testValue}, "clean", "-control")
	if rc != 2 || !strings.Contains(out, "blind to needle") {
		t.Fatalf("rc=%d %s", rc, out)
	}
}
