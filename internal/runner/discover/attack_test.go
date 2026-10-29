package discover

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// Independent fixtures produced by Python plistlib, including UTF-16 text.
func TestBinaryPlist(t *testing.T) {
	k := key(t, "scan")
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(old)
	slog.Info("capture-control")
	if logs.Len() == 0 {
		t.Fatal("log capture blind")
	}
	for _, tc := range []struct{ body, value string }{
		{"YnBsaXN0MDDSAQIDBl8QFEVudmlyb25tZW50VmFyaWFibGVzVUxhYmVs0QQFV0FQSV9LRVlfEBRzeW50aGV0aWMtYmluYXJ5LWEmYl50ZXN0LmRpc2NvdmVyeQgNJCotNUwAAAAAAAABAQAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAWw==", "synthetic-binary-a&b"},
		{"YnBsaXN0MDDSAQIDBl8QFEVudmlyb25tZW50VmFyaWFibGVzVUxhYmVs0QQFV0FQSV9LRVlvEBMAcwB5AG4AdABoAGUAdABpAGMALQBiAGkAbgBhAHIAeQAt2D3dEV50ZXN0LmRpc2NvdmVyeQgNJCotNV4AAAAAAAABAQAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAbQ==", "synthetic-binary-\U0001f511"},
	} {
		body, err := base64.StdEncoding.DecodeString(tc.body)
		if err != nil {
			t.Fatal("decode fixture")
		}
		root := fixtureDir(t)
		put(t, root, "carrier", string(body))
		got, err := Scan(context.Background(), policy(root, LaunchdPlist, "carrier"), k)
		if err != nil || len(got) != 1 {
			t.Fatal("binary plist rejected")
		}
		if got[0].Fingerprint != fp(t, k, tc.value) || got[0].Len != len(tc.value) {
			t.Error("binary string decoded incorrectly")
		}
		c := canary.Of(tc.value)
		if !c.In("positive " + tc.value) {
			t.Fatal("binary canary detector blind")
		}
		encoded, e := json.Marshal(got)
		if e != nil {
			t.Fatal("marshal binary findings")
		}
		for _, sink := range []string{fmt.Sprintf("%v", got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got), string(encoded), logs.String()} {
			if c.In(sink) {
				t.Error("binary value leaked in finding or log")
			}
		}
		// Truncated trailers, oversized offsets and a cycle must fail closed.
		for _, bad := range [][]byte{body[:len(body)-1], append(bytes.Clone(body), 0), append([]byte("bplist00"), bytes.Repeat([]byte{255}, 40)...)} {
			put(t, root, "carrier", string(bad))
			out, e := Scan(context.Background(), policy(root, LaunchdPlist, "carrier"), k)
			if e == nil || len(out) != 0 {
				t.Error("malformed binary accepted")
			}
			encoded, marshalErr := json.Marshal(out)
			if marshalErr != nil {
				t.Fatal("marshal malformed binary findings")
			}
			for _, sink := range []string{fmt.Sprintf("%v %+v %#v", out, out, out), string(encoded), logs.String()} {
				if c.In(sink) {
					t.Error("malformed binary value leaked in finding or log")
				}
			}
			for cause := e; cause != nil; cause = errors.Unwrap(cause) {
				if c.In(fmt.Sprintf("%v %+v %#v", cause, cause, cause)) {
					t.Error("binary value leaked in parse error chain")
				}
			}
		}
	}
}

func TestLiteralParsingAndNoExecution(t *testing.T) {
	k := key(t, "scan")
	for _, tc := range []struct {
		kind        Kind
		body, value string
	}{
		{EnvFile, "export API_KEY=' leading and trailing '\n", " leading and trailing "},
		{EnvFile, "API_KEY='apostrophe'\\''tail'\n", "apostrophe'tail"},
		{EnvFile, "API_KEY=\"literal\\$dollar\"\n", "literal$dollar"},
		{MCPConfig, `{"mcpServers":{"a":{"env":{"API_KEY":"a\nb\uD83D\uDD11"}}}}`, "a\nb\U0001f511"},
		{LaunchdPlist, `<plist><dict><key>EnvironmentVariables</key><dict><key>API_KEY</key><string>a&amp;b</string></dict></dict></plist>`, "a&b"},
		{SystemdUnit, "[Service]\nEnvironment=API_KEY=discard\nEnvironment=\nEnvironment=\"API_KEY=a\\nb\"\n", "a\nb"},
	} {
		root := fixtureDir(t)
		put(t, root, "carrier", tc.body)
		got, e := Scan(context.Background(), policy(root, tc.kind, "carrier"), k)
		if e != nil || len(got) != 1 || got[0].Fingerprint != fp(t, k, tc.value) {
			t.Error("literal decoder disagrees")
		}
	}
	root := fixtureDir(t)
	marker := filepath.Join(root, "executed")
	for _, body := range []string{"API_KEY=$(touch " + marker + ")", "API_KEY=${OTHER}", "API_KEY= command", "API_KEY=`touch " + marker + "`", "API_KEY='unterminated", "API_KEY='a'\nAPI_KEY='b'"} {
		put(t, root, "carrier", body)
		got, e := Scan(context.Background(), policy(root, EnvFile, "carrier"), k)
		if e == nil || len(got) != 0 {
			t.Error("ambiguous syntax accepted")
		}
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Error("parser executed input")
	}
}

func TestUnknownNamesAndDuplicateJSON(t *testing.T) {
	c := canary.New()
	k := key(t, "scan")
	root := fixtureDir(t)
	put(t, root, "carrier", strings.ReplaceAll(c.Value(1), "-", "_")+"=synthetic\nAPI_KEY='synthetic'\n")
	got, e := Scan(context.Background(), policy(root, EnvFile, "carrier"), k)
	if e != nil || len(got) != 1 || got[0].Name != "API_KEY" || c.In(fmt.Sprintf("%#v", got)) {
		t.Fatal("untrusted name became metadata")
	}
	for _, body := range []string{
		`{"mcpServers":{"a":{"env":{"API_KEY":"a","API_KEY":"b"}}}}`,
		`{"mcpServers":{"a":{"env":{"API_KEY":"a","\u0041PI_KEY":"b"}}}}`,
		`{"mcpServers":{"a":{"env":{"API_KEY":42}}}}`,
		`{"mcpServers":{"a":{"env":{"API_KEY":"\uD800"}}}}`,
	} {
		put(t, root, "carrier", body)
		if out, e := Scan(context.Background(), policy(root, MCPConfig, "carrier"), k); e == nil || len(out) != 0 {
			t.Error("ambiguous MCP accepted")
		}
	}
}

func TestHardlinksPermissionsAndAtomicFailure(t *testing.T) {
	root := fixtureDir(t)
	k := key(t, "scan")
	put(t, root, "good.env", "API_KEY='synthetic'\n")
	if e := os.Link(filepath.Join(root, "good.env"), filepath.Join(root, "hard.env")); e != nil {
		t.Fatal("link fixture")
	}
	if got, e := Scan(context.Background(), policy(root, EnvFile, "hard.env"), k); e == nil || len(got) != 0 {
		t.Error("hardlink read")
	}
	if e := os.Remove(filepath.Join(root, "hard.env")); e != nil {
		t.Fatal("unlink fixture")
	}
	if e := os.Chmod(filepath.Join(root, "good.env"), 0o666); e != nil { //nolint:gosec // Deliberately insecure test fixture; scanner must reject it.
		t.Fatal("mode fixture")
	}
	if got, e := Scan(context.Background(), policy(root, EnvFile, "good.env"), k); e == nil || len(got) != 0 {
		t.Error("writable carrier read")
	}
	if e := os.Chmod(filepath.Join(root, "good.env"), 0o600); e != nil {
		t.Fatal("mode restore")
	}
	put(t, root, "bad.env", "API_KEY='unterminated")
	if got, e := Scan(context.Background(), policy(root, EnvFile, "*.env"), k); e == nil || len(got) != 0 {
		t.Error("partial inventory returned")
	}
	put(t, root, "bad.env", "API_KEY='also synthetic'\n")
	p := policy(root, EnvFile, "*.env")
	p.MaxFiles = 1
	if got, e := Scan(context.Background(), p, k); !errors.Is(e, ErrPolicy) || len(got) != 0 {
		t.Error("file-count limit ignored")
	}
	p.MaxFiles = 32
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e := Scan(ctx, p, k); !errors.Is(e, ErrCanceled) || len(got) != 0 {
		t.Error("cancel ignored")
	}
}

func TestFullFingerprintAndTenantKeys(t *testing.T) {
	k := key(t, "scan")
	other := key(t, "other")
	value := strings.Repeat("same-long-prefix", 4)
	base := fp(t, k, value)
	for _, v := range []string{value + "x", value[:len(value)-1], value + " ", value + "\n"} {
		got, e := Compare(k, []Finding{{Path: "file", Name: "API_KEY", Fingerprint: fp(t, k, v)}}, []KnownCarrier{{Path: "file", Name: "API_KEY", Fingerprint: base, Active: true}})
		if e != nil || len(got) != 1 || got[0].Verdict != Stale {
			t.Error("full value change missed")
		}
	}
	if fp(t, k, value) == fp(t, other, value) {
		t.Error("tenant keys did not separate")
	}
	for _, bad := range []string{strings.Repeat("a", 64), fp(t, other, value)} {
		if _, e := Compare(k, []Finding{{Path: "file", Name: "API_KEY", Fingerprint: bad}}, []KnownCarrier{{Path: "file", Name: "API_KEY", Fingerprint: base}}); !errors.Is(e, ErrFingerprint) {
			t.Error("foreign or bare digest accepted")
		}
	}
}

func TestBufferGrowthWipesOldCopy(t *testing.T) {
	old := []byte("synthetic-buffer")
	got := appendWiped(old, bytes.Repeat([]byte{'x'}, 64))
	if !bytes.Equal(old, make([]byte, len(old))) || !bytes.HasPrefix(got, []byte("synthetic-buffer")) {
		t.Fatal("old value backing array not wiped")
	}
	wipe(got)
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("current buffer not wiped")
	}
}

func TestMultipleGlobRules(t *testing.T) {
	root := fixtureDir(t)
	k := key(t, "scan")
	put(t, root, "a.env", "API_KEY='synthetic-a'\n")
	put(t, root, "b.cred", "synthetic-b")
	p := policy(root, EnvFile, "*.env")
	p.Rules = append(p.Rules, Rule{Glob: "*.cred", Kind: Credential, Names: []string{"API_KEY"}})
	got, e := Scan(context.Background(), p, k)
	if e != nil || len(got) != 2 {
		t.Fatal("independent glob rules lost directory entries")
	}
}

func TestParserResourceBounds(t *testing.T) {
	k := key(t, "scan")
	root := fixtureDir(t)
	put(t, root, "carrier", strings.Repeat("UNLISTED=x\n", 5000))
	if out, e := Scan(context.Background(), policy(root, EnvFile, "carrier"), k); e == nil || len(out) != 0 {
		t.Error("unbounded env entries accepted")
	}
	var data strings.Builder
	data.WriteString(`{"mcpServers":{"a":{"env":{`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			data.WriteByte(',')
		}
		fmt.Fprintf(&data, "\"UNLISTED_%d\":\"x\"", i)
	}
	data.WriteString(`}}}}`)
	put(t, root, "carrier", data.String())
	if out, e := Scan(context.Background(), policy(root, MCPConfig, "carrier"), k); e == nil || len(out) != 0 {
		t.Error("unbounded JSON dictionary accepted")
	}
}

func TestMissingFileScansAsUnknownFind(t *testing.T) {
	root := fixtureDir(t)
	k := key(t, "scan")
	findings, e := Scan(context.Background(), policy(root, EnvFile, "absent.env"), k)
	if e != nil || len(findings) != 0 {
		t.Fatal("absent permitted file is not a read failure")
	}
	got, e := Compare(k, findings, []KnownCarrier{{Path: "absent.env", Name: "API_KEY", Fingerprint: fp(t, k, "synthetic"), Active: true}})
	if e != nil || len(got) != 1 || got[0].Verdict != UnknownFind {
		t.Fatal("absent active carrier must be unknown_find")
	}
}

func TestWritableRootRefused(t *testing.T) {
	root := fixtureDir(t)
	k := key(t, "scan")
	put(t, root, "carrier", "API_KEY='synthetic'\n")
	if e := os.Chmod(root, 0o777); e != nil { //nolint:gosec // Deliberately writable test-owned directory.
		t.Fatal("set root mode")
	} //nolint:gosec // Intentionally unsafe temporary policy root.
	defer func() { _ = os.Chmod(root, 0o700) }() //nolint:gosec // Restore private directory permissions, not file permissions.
	if out, e := Scan(context.Background(), policy(root, EnvFile, "carrier"), k); e == nil || len(out) != 0 {
		t.Fatal("writable policy root accepted")
	}
}

func TestWritableRootAncestorRefused(t *testing.T) {
	base := fixtureDir(t)
	put(t, base, "parent/root/carrier", "API_KEY='synthetic'\n")
	k := key(t, "scan")
	p := policy(filepath.Join(base, "parent", "root"), EnvFile, "carrier")
	if got, err := Scan(context.Background(), p, k); err != nil || len(got) != 1 {
		t.Fatal("protected ancestor positive control refused")
	}
	parent := filepath.Join(base, "parent")
	if err := os.Chmod(parent, 0o777); err != nil { //nolint:gosec // Deliberately unsafe directory in a private test fixture.
		t.Fatal("writable ancestor fixture")
	}
	defer func() { _ = os.Chmod(parent, 0o700) }() //nolint:gosec // Restore private fixture directory permissions for cleanup.
	if got, err := Scan(context.Background(), p, k); !errors.Is(err, ErrRead) || len(got) != 0 {
		t.Fatal("writable policy-root ancestor accepted")
	}
}

func TestMissingInactiveCarrierIgnored(t *testing.T) {
	k := key(t, "scan")
	f := fp(t, k, "synthetic")
	got, err := Compare(k, nil, []KnownCarrier{
		{Path: "inactive", Name: "API_KEY", Fingerprint: f, Active: false},
		{Path: "active", Name: "API_KEY", Fingerprint: f, Active: true},
	})
	if err != nil || len(got) != 1 || got[0].Finding.Path != "active" || got[0].Verdict != UnknownFind {
		t.Fatal("missing inactive carrier classified or active control missing")
	}
}

func TestTrustedOwnersRequired(t *testing.T) {
	root := fixtureDir(t)
	put(t, root, "carrier", "API_KEY='synthetic'\n")
	k := key(t, "scan")
	p := policy(root, EnvFile, "carrier")
	if got, err := Scan(context.Background(), p, k); err != nil || len(got) != 1 {
		t.Fatal("trusted owner positive control refused")
	}
	p.TrustedUIDs = []uint32{^uint32(0)}
	if got, err := Scan(context.Background(), p, k); !errors.Is(err, ErrRead) || len(got) != 0 {
		t.Fatal("untrusted owner admitted")
	}
	p.TrustedUIDs = nil
	if got, err := Scan(context.Background(), p, k); !errors.Is(err, ErrPolicy) || len(got) != 0 {
		t.Fatal("absent owner policy admitted")
	}
}

func TestUnmatchedDirectoryEntriesBounded(t *testing.T) {
	root := fixtureDir(t)
	put(t, root, "wanted.env", "API_KEY='synthetic'\n")
	k := key(t, "scan")
	p := policy(root, EnvFile, "wanted*.env")
	p.MaxFiles = 1
	if got, err := Scan(context.Background(), p, k); err != nil || len(got) != 1 {
		t.Fatal("bounded enumeration positive control refused")
	}
	for i := range 65 {
		put(t, root, fmt.Sprintf("unmatched-%d", i), "ignored")
	}
	if got, err := Scan(context.Background(), p, k); !errors.Is(err, ErrPolicy) || len(got) != 0 {
		t.Fatal("unmatched enumeration exceeded budget")
	}
}

func FuzzParsers(f *testing.F) {
	for _, s := range []string{"API_KEY='synthetic'", "[Service]\nEnvironment=API_KEY=synthetic", `{"mcpServers":{"a":{"env":{"API_KEY":"synthetic"}}}}`, "<plist><dict/></plist>", "bplist00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		for _, kind := range []Kind{EnvFile, SystemdUnit, LaunchdPlist, MCPConfig} {
			_, err := parseCarrier([]byte(s), Rule{Kind: kind, Names: []string{"API_KEY"}}, "carrier", key(t, "scan"))
			if err != nil && !errors.Is(err, ErrParse) && !errors.Is(err, ErrFingerprint) {
				t.Fatal("non-fixed parse error")
			}
		}
	})
}
