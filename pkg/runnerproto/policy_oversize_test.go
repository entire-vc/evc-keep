//go:build unix

// Diagnostics in this file are deliberately static: a failing assertion must
// never print the Load error, which on a leaking mutant carries file content.
package runnerproto

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// wantOversizeRefusal is the whole refusal text: any content, size or wrapped
// cause appended to it, however short, changes it.
const wantOversizeRefusal = "runnerproto: host policy exceeds the size limit"

const policyOversizeBody = `{"version":1,"targets":[],"max_deploys_per_hour":1}`

// writePolicyPadded writes the valid policy, whitespace up to exactly total
// bytes, then tail (if any) after it; the file has mode 0600.
func writePolicyPadded(t *testing.T, total int, tail string) string {
	t.Helper()
	return writePolicyWithBody(t, policyOversizeBody, total, tail)
}

func writePolicyWithBody(t *testing.T, body string, total int, tail string) string {
	t.Helper()
	if len(body) > total {
		t.Fatalf("fixture: body longer than target size %d", total)
	}
	b := append([]byte(body), bytes.Repeat([]byte(" "), total-len(body))...)
	b = append(b, tail...)
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

// TestLoadHostPolicyOversize: a policy file past the 1 MiB cap is refused, not
// truncated to its first MiB and accepted on the strength of a valid prefix
// (the tail may be anything, including the part ParseHostPolicy would refuse).
// The exact cap loads, cap+1 does not; the error carries no file content.
func TestLoadHostPolicyOversize(t *testing.T) {
	const limit = 1 << 20
	uid := os.Getuid()

	// Positive controls: ordinary file, and exactly limit bytes.
	if _, err := LoadHostPolicy(writePolicyPadded(t, len(policyOversizeBody), ""), uid); err != nil {
		t.Fatal("positive control: regular policy refused")
	}
	if _, err := LoadHostPolicy(writePolicyPadded(t, limit, ""), uid); err != nil {
		t.Fatalf("file of exactly %d bytes must load", limit)
	}

	// Detector positive control: the canary check sees a canary.
	c := canary.New()
	cv := c.Value(0)
	if !c.In("x " + cv + " y") {
		t.Fatal("detector control: canary not detected")
	}

	// The canary sits at the head of the file, where a refusal that quotes
	// the start of what it read would carry it; the whole file is refused on
	// size before any parsing, so the head need not be a valid policy.
	head := writePolicyWithBody(t, `{"note":"`+cv+`"}`, limit, " ")
	if _, err := LoadHostPolicy(head, uid); err == nil {
		t.Error("head-canary: oversized file accepted")
	} else if err.Error() != wantOversizeRefusal {
		t.Error("head-canary: refusal is not the exact static text")
	} else if c.In(err.Error()) {
		t.Error("head-canary: error reflects file content")
	}

	cases := map[string]string{
		"one-whitespace-byte": " ",
		"malformed-suffix":    "INVALID",
		"canary-suffix":       "\n" + cv,
		"valid-second-doc":    "\n" + policyOversizeBody,
	}
	for name, tail := range cases {
		p := writePolicyPadded(t, limit, tail)
		pol, err := LoadHostPolicy(p, uid)
		if err == nil {
			t.Errorf("%s: oversized policy accepted", name)
			continue
		}
		if pol.Version != 0 || pol.MaxDeploysPerHour != 0 {
			t.Errorf("%s: partially parsed policy returned with the refusal", name)
		}
		if err.Error() != wantOversizeRefusal {
			t.Errorf("%s: refusal is not the exact static text", name)
		}
		msg := err.Error()
		if c.In(msg) || strings.Contains(msg, "INVALID") {
			t.Errorf("%s: error reflects file content", name)
		}
		for _, n := range []int{limit, limit + 1, limit + len(tail)} {
			if strings.Contains(msg, strconv.Itoa(n)) {
				t.Errorf("%s: error carries a file size", name)
			}
		}
	}

	// Source file is untouched by the refusal.
	p := writePolicyPadded(t, limit, "INVALID")
	before, err := os.ReadFile(p) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatal("read policy before")
	}
	_, _ = LoadHostPolicy(p, uid)
	after, err := os.ReadFile(p) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatal("read policy after")
	}
	if !bytes.Equal(before, after) {
		t.Error("policy file modified by Load")
	}
}
