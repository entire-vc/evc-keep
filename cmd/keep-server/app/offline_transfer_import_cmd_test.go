package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

const abcUID = "abcdefab-abcd-4bcd-8bcd-abcdefabcdef"

const (
	pinHex  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	someUID = "abcdefab-abcd-4bcd-8bcd-abcdefabcdef"
)

func importArgs(d string, over map[string]string) []string {
	m := map[string]string{
		"--bundle": filepath.Join(d, "b.sealed"), "--private-file": filepath.Join(d, "r.key"),
		"--public-file": filepath.Join(d, "r.pub"), "--approval": filepath.Join(d, "approval.json"), "--transfer": someUID, "--source": someUID,
		"--target": someUID, "--snapshot": someUID, "--org": someUID, "--workspace": someUID,
		"--schema": "50", "--expect-checksum": pinHex, "--expect-recipient-fingerprint": pinHex, "--expect-approval-checksum": pinHex,
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

// The refusals must be static lines: neither a canary planted in the DSN or
// the root path nor any carrier content may reach stdout or stderr.
func TestTransferImportRefusalsAreStaticAndLeakNothing(t *testing.T) {
	d := carrierDir(t)
	c := canary.New()
	t.Setenv("KEEP_DATABASE_URL", "postgres://u:"+c.Value(0)+"@127.0.0.1:1/x")
	t.Setenv("KEEP_ROOT_KEY_FILE", filepath.Join(d, "root-"+c.Value(0)))
	if err := os.WriteFile(filepath.Join(d, "b.sealed"), []byte(c.Value(0)), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		over   map[string]string
		reason string
	}{
		"bad checksum pin":    {map[string]string{"--expect-checksum": "zz"}, "pin"},
		"bad fingerprint pin": {map[string]string{"--expect-recipient-fingerprint": "ab"}, "pin"},
		"bad approval pin":    {map[string]string{"--expect-approval-checksum": "zz"}, "pin"},
		"bad identity":        {map[string]string{"--org": "not-a-uuid"}, "identity"},
		"uppercase identity":  {map[string]string{"--org": strings.ToUpper(someUID)}, "identity"},
		"relative bundle":     {map[string]string{"--bundle": "b.sealed"}, "carrier_path"},
		"bundle checksum":     {nil, "checksum"},
	}
	for name, tc := range cases {
		code, out, errs := runTransfer(append([]string{"import"}, importArgs(d, tc.over)...)...)
		if code == 0 || !strings.Contains(errs, "reason="+tc.reason) {
			t.Fatalf("%s: code=%d stderr=%q", name, code, errs)
		}
		if c.In(out) || c.In(errs) {
			t.Fatalf("%s: canary reached output", name)
		}
	}
	// Correct pins must get past each comparison to the next stage.
	sum := sha256.Sum256([]byte(c.Value(0)))
	pub := []byte("public-carrier-bytes")
	if err := os.WriteFile(filepath.Join(d, "r.pub"), pub, 0o600); err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(pub)
	good := map[string]string{"--expect-checksum": hex.EncodeToString(sum[:]), "--expect-recipient-fingerprint": hex.EncodeToString(fp[:])}
	for name, tc := range map[string]struct {
		over   map[string]string
		reason string
	}{
		"checksum ok, recipient wrong": {map[string]string{"--expect-checksum": good["--expect-checksum"]}, "recipient"},
		"both ok, private carrier":     {good, "carrier_open"},
	} {
		code, out, errs := runTransfer(append([]string{"import"}, importArgs(d, tc.over)...)...)
		if code == 0 || !strings.Contains(errs, "reason="+tc.reason) || c.In(out) || c.In(errs) {
			t.Fatalf("%s: code=%d stderr=%q", name, code, errs)
		}
	}
	// With a readable private carrier the next refusals are the installation's
	// own root and the bundle itself.
	if err := os.WriteFile(filepath.Join(d, "r.key"), []byte("private-carrier-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ root, reason string }{
		"no usable root":             {filepath.Join(d, "absent-root"), "root"},
		"root ok, bundle unreadable": {"", "bundle"},
	} {
		if tc.root == "" {
			tc.root, _ = writeRootFile(t, d, "local-v1")
		}
		t.Setenv("KEEP_ROOT_KEY_FILE", tc.root)
		code, out, errs := runTransfer(append([]string{"import"}, importArgs(d, good)...)...)
		if code == 0 || !strings.Contains(errs, "reason="+tc.reason) || c.In(out) || c.In(errs) {
			t.Fatalf("%s: code=%d stderr=%q", name, code, errs)
		}
	}
	// Positive control: the canary check can see a leak.
	if !c.In("x" + c.Value(0)) {
		t.Fatal("canary is blind")
	}
}

func TestTransferImportRequiresAllFlagsAndNoDSNInArgv(t *testing.T) {
	d := carrierDir(t)
	for _, miss := range []string{"--bundle", "--private-file", "--public-file", "--approval", "--transfer", "--source", "--target", "--snapshot", "--org", "--workspace", "--schema", "--expect-checksum", "--expect-recipient-fingerprint", "--expect-approval-checksum"} {
		code, _, errs := runTransfer(append([]string{"import"}, importArgs(d, map[string]string{miss: ""})...)...)
		if code != 2 || !strings.Contains(errs, "usage") {
			t.Fatalf("missing %s: code=%d %q", miss, code, errs)
		}
	}
	code, _, _ := runTransfer(append([]string{"import", "--dsn", "x"}, importArgs(d, nil)...)...)
	if code != 2 {
		t.Fatal("a DSN flag must not exist")
	}
}

func TestApprovalMatchesOnlyTheSameTransfer(t *testing.T) {
	id := func() string { return uuid.NewString() }
	b := approvalBinding{
		Transfer: id(), Source: id(), Target: id(), Snapshot: id(), Org: id(), Workspace: id(), Schema: 51,
		Checksum: strings.Repeat("a", 64), ClosureDigest: "sha256:" + strings.Repeat("b", 64), AuditHead: "head-1",
	}
	mk := func(mutate func(*transferApproval)) []byte {
		a := transferApproval{transferCheckpoint: transferCheckpoint{
			Version: 1, OrgID: b.Org, WorkspaceID: b.Workspace, TransferID: b.Transfer, SnapshotID: b.Snapshot,
			SourceID: b.Source, TargetID: b.Target, Schema: 51, ClosureDigest: b.ClosureDigest,
			AuditHead: b.AuditHead, Rows: 3, CiphertextChecksum: b.Checksum,
		}, Quiescence: "asserted", Status: "final"}
		if mutate != nil {
			mutate(&a)
		}
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if !approvalMatches(mk(nil), b) {
		t.Fatal("positive control: the matching final approval was refused")
	}
	for name, raw := range map[string][]byte{
		"transfer":     mk(func(a *transferApproval) { a.TransferID = id() }),
		"source":       mk(func(a *transferApproval) { a.SourceID = id() }),
		"target":       mk(func(a *transferApproval) { a.TargetID = id() }),
		"snapshot":     mk(func(a *transferApproval) { a.SnapshotID = id() }),
		"org":          mk(func(a *transferApproval) { a.OrgID = id() }),
		"workspace":    mk(func(a *transferApproval) { a.WorkspaceID = id() }),
		"schema":       mk(func(a *transferApproval) { a.Schema = 52 }),
		"checksum":     mk(func(a *transferApproval) { a.CiphertextChecksum = strings.Repeat("c", 64) }),
		"digest":       mk(func(a *transferApproval) { a.ClosureDigest = "sha256:" + strings.Repeat("d", 64) }),
		"audit head":   mk(func(a *transferApproval) { a.AuditHead = "head-2" }),
		"not final":    mk(func(a *transferApproval) { a.Status = "pending" }),
		"no freeze":    mk(func(a *transferApproval) { a.Quiescence = "" }),
		"empty":        nil,
		"not json":     []byte("final"),
		"extra field":  append(bytes.TrimSuffix(mk(nil), []byte("}")), []byte(`,"extra":1}`)...),
		"spaced":       bytes.Replace(mk(nil), []byte(`"status":"final"`), []byte(`"status": "final"`), 1),
		"zero version": mk(func(a *transferApproval) { a.Version = 0 }),
	} {
		if approvalMatches(raw, b) {
			t.Fatalf("approval accepted despite a different %s", name)
		}
	}
}

// The approval is hashed as the very bytes that are then parsed, against a pin
// that only the source operator holds. A file assembled from the bundle's own
// public metadata (which is all an exporter's counterpart can see) describes
// the right transfer, so field matching alone cannot tell it from the real
// finalize output.
func TestVerifyApprovalNeedsTheIndependentPin(t *testing.T) {
	id := func() string { return uuid.NewString() }
	b := approvalBinding{
		Transfer: id(), Source: id(), Target: id(), Snapshot: id(), Org: id(), Workspace: id(), Schema: 51,
		Checksum: strings.Repeat("a", 64), ClosureDigest: "sha256:" + strings.Repeat("b", 64), AuditHead: "head-1",
	}
	mk := func(rows int64) []byte {
		raw, err := json.Marshal(transferApproval{transferCheckpoint: transferCheckpoint{
			Version: 1, OrgID: b.Org, WorkspaceID: b.Workspace, TransferID: b.Transfer, SnapshotID: b.Snapshot,
			SourceID: b.Source, TargetID: b.Target, Schema: 51, ClosureDigest: b.ClosureDigest,
			AuditHead: b.AuditHead, Rows: rows, CiphertextChecksum: b.Checksum,
		}, Quiescence: "asserted", Status: "final"})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	pinOf := func(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
	real, forged := mk(3), mk(4) // same bindings, different bytes: another finalize
	if got := verifyApproval(real, pinOf(real), b); got != "" {
		t.Fatalf("positive control: the real approval with its pin was refused: %q", got)
	}
	for name, tc := range map[string]struct {
		raw []byte
		pin string
	}{
		"forged approval, real pin": {forged, pinOf(real)},
		"real approval, forged pin": {real, pinOf(forged)},
		"bundle checksum as pin":    {real, b.Checksum},
		"missing pin":               {real, ""},
		"malformed pin":             {real, "zz"},
		"uppercase pin":             {real, strings.ToUpper(pinOf(real))},
		"pin of an empty carrier":   {real, pinOf(nil)},
		"approval with a trailer":   {append(append([]byte{}, real...), '\n'), pinOf(real)},
	} {
		if got := verifyApproval(tc.raw, tc.pin, b); got != "approval_pin" {
			t.Fatalf("%s: want approval_pin, got %q", name, got)
		}
	}
	// A matching pin does not excuse a wrong transfer.
	other := b
	other.Snapshot = id()
	if got := verifyApproval(real, pinOf(real), other); got != "approval" {
		t.Fatalf("pinned approval for another snapshot: want approval, got %q", got)
	}
}
