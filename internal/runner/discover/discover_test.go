package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func key(t *testing.T, id string) fingerprint.Key {
	t.Helper()
	k, err := fingerprint.GenerateKey(id)
	if err != nil {
		t.Fatal("generate test key")
	}
	t.Cleanup(k.Wipe)
	return k
}

// Fixtures need protected ancestors as well as a private leaf. The shared
// system temporary directory can be world-writable, so use a private home child.
func fixtureDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("fixture home unavailable")
	}
	root, err := os.MkdirTemp(home, ".keep-discovery-test-")
	if err != nil {
		t.Fatal("create protected fixture root")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("remove fixture root")
		}
	})
	return root
}

func put(t *testing.T, root, path, content string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal("mkdir fixture")
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal("write fixture")
	}
}

func policy(root string, kind Kind, glob string) Policy {
	root, _ = filepath.EvalSymlinks(root)
	uid := uint32(os.Getuid()) //nolint:gosec // Unix getuid returns a uid_t, which fits uint32; used only by test policy.
	return Policy{Root: root, Rules: []Rule{{Glob: glob, Kind: kind, Names: []string{"API_KEY"}}}, MaxBytes: 1 << 16, MaxFiles: 32, TrustedUIDs: []uint32{0, uid}}
}

func fp(t *testing.T, k fingerprint.Key, value string) string {
	t.Helper()
	v := secret.New([]byte(value))
	defer v.Wipe()
	f, err := fingerprint.Compute(k, v)
	if err != nil {
		t.Fatal("test fingerprint")
	}
	return f
}

func TestCanarySurfaces(t *testing.T) {
	c := canary.New()
	if !c.In("positive " + c.Value(1)) {
		t.Fatal("detector blind")
	}
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(old)
	slog.Info("capture-control")
	if logs.Len() == 0 {
		t.Fatal("log capture blind")
	}
	k := key(t, "scan")
	for _, tc := range []struct {
		kind Kind
		body string
	}{
		{EnvFile, "API_KEY='" + c.Value(1) + "'\n"},
		{LaunchdPlist, `<?xml version="1.0"?><plist version="1.0"><dict><key>EnvironmentVariables</key><dict><key>API_KEY</key><string>` + c.Value(1) + `</string></dict></dict></plist>`},
		{SystemdUnit, "[Service]\nEnvironment=\"API_KEY=" + c.Value(1) + "\"\n"},
		{Credential, c.Value(1)},
		{MCPConfig, `{"mcpServers":{"test":{"env":{"API_KEY":"` + c.Value(1) + `"}}}}`},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			root := fixtureDir(t)
			put(t, root, "carrier", tc.body)
			findings, err := Scan(context.Background(), policy(root, tc.kind, "carrier"), k)
			if err != nil || len(findings) != 1 {
				t.Fatal("valid carrier rejected")
			}
			if findings[0].Fingerprint != fp(t, k, c.Value(1)) || findings[0].Len != len(c.Value(1)) {
				t.Error("wrong fingerprint or length")
			}
			encoded, e := json.Marshal(findings)
			if e != nil {
				t.Fatal("marshal")
			}
			for _, out := range []string{fmt.Sprintf("%v", findings), fmt.Sprintf("%+v", findings), fmt.Sprintf("%#v", findings), string(encoded), logs.String()} {
				if c.In(out) {
					t.Error("canary in result or log")
				}
			}
			put(t, root, "carrier", tc.body+"\x00"+c.Value(1))
			bad, err := Scan(context.Background(), policy(root, tc.kind, "carrier"), k)
			// Credentials are arbitrary bytes, so the appended input remains valid.
			if tc.kind != Credential && (err == nil || len(bad) != 0) {
				t.Error("malformed input accepted or partial result returned")
			}
			if err != nil {
				for e := err; e != nil; e = errors.Unwrap(e) {
					if c.In(fmt.Sprintf("%v %+v %#v", e, e, e)) {
						t.Error("canary in parse error")
					}
				}
			}
		})
	}
}

func TestFindingSchema(t *testing.T) {
	for _, tc := range []struct {
		v     any
		names []string
	}{
		{Finding{}, []string{"Path", "Name", "Fingerprint", "Len"}},
		{Observation{}, []string{"Finding", "Verdict"}},
	} {
		typ := reflect.TypeOf(tc.v)
		if typ.NumField() != len(tc.names) {
			t.Fatal("open result schema")
		}
		for i, n := range tc.names {
			if typ.Field(i).Name != n {
				t.Fatal("unexpected result field")
			}
		}
	}
}

func TestClassification(t *testing.T) {
	k := key(t, "scan")
	old := fp(t, k, "synthetic-old")
	fresh := fp(t, k, "synthetic-new")
	findings := []Finding{{Path: "same", Name: "API_KEY", Fingerprint: old}, {Path: "changed", Name: "API_KEY", Fingerprint: fresh}, {Path: "extra", Name: "API_KEY", Fingerprint: fresh}}
	known := []KnownCarrier{{Path: "same", Name: "API_KEY", Fingerprint: old, Active: true}, {Path: "changed", Name: "API_KEY", Fingerprint: old, Active: true}, {Path: "absent", Name: "API_KEY", Fingerprint: old, Active: true}}
	got, err := Compare(k, findings, known)
	if err != nil || len(got) != 4 {
		t.Fatal("classification failed")
	}
	want := []Verdict{Match, Stale, Sprawl, UnknownFind}
	for i, w := range want {
		if got[i].Verdict != w {
			t.Errorf("wrong classification at %d", i)
		}
	}
}

func TestMissingActiveIsUnknownFind(t *testing.T) {
	k := key(t, "scan")
	got, err := Compare(k, nil, []KnownCarrier{{Path: "missing", Name: "API_KEY", Fingerprint: fp(t, k, "synthetic"), Active: true}})
	if err != nil || len(got) != 1 || got[0].Verdict != UnknownFind || string(got[0].Verdict) != "unknown_find" {
		t.Fatal("missing active carrier must be unknown_find")
	}
}

func TestPolicyAndSymlinks(t *testing.T) {
	root := fixtureDir(t)
	outside := fixtureDir(t)
	put(t, outside, "outside", "API_KEY='synthetic-outside'\n")
	k := key(t, "scan")
	for _, pattern := range []string{"../outside", filepath.Join(outside, "outside"), "~/*", "**/*", ""} {
		got, err := Scan(context.Background(), policy(root, EnvFile, pattern), k)
		if err == nil || len(got) != 0 {
			t.Error("outside pattern accepted")
		}
	}
	if err := os.Symlink(filepath.Join(outside, "outside"), filepath.Join(root, "link")); err != nil {
		t.Fatal("symlink fixture")
	}
	if got, err := Scan(context.Background(), policy(root, EnvFile, "link"), k); err == nil || len(got) != 0 {
		t.Error("outside symlink read")
	}
	if err := os.Symlink(outside, filepath.Join(root, "directory")); err != nil {
		t.Fatal("directory symlink")
	}
	if got, err := Scan(context.Background(), policy(root, EnvFile, "directory/*"), k); err == nil || len(got) != 0 {
		t.Error("symlinked parent read")
	}
	put(t, root, "allowed", "API_KEY='synthetic-inside'\n")
	if got, err := Scan(context.Background(), policy(root, EnvFile, "allowed"), k); err != nil || len(got) != 1 {
		t.Fatal("allowed positive control refused")
	}
}

func TestSizeLimitNoRead(t *testing.T) {
	root := fixtureDir(t)
	put(t, root, "large", strings.Repeat("x", 65))
	k := key(t, "scan")
	p := policy(root, Credential, "large")
	p.MaxBytes = 64
	if got, err := Scan(context.Background(), p, k); !errors.Is(err, ErrSize) || len(got) != 0 {
		t.Error("oversized file accepted")
	}
	f, err := os.Open(filepath.Join(root, "large")) //nolint:gosec // Test-owned temporary fixture, never a supplied host path.
	if err != nil {
		t.Fatal("open fixture")
	}
	defer func() { _ = f.Close() }()
	data, err := readBounded(f, 64)
	pos, e := f.Seek(0, 1)
	if !errors.Is(err, ErrSize) || len(data) != 0 || e != nil || pos != 0 {
		t.Error("oversized carrier partially read")
	}
}
