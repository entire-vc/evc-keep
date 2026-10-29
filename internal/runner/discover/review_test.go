package discover

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

func TestEnvDoubleQuotedEscapes(t *testing.T) {
	k := key(t, "scan")
	for _, tc := range []struct {
		name, body, value string
		bad               bool
	}{
		{"double-space", `API_KEY="synthetic\ tail"`, "", true},
		{"double-tab", "API_KEY=\"synthetic\\\ttail\"", "", true},
		{"double-single-quote", `API_KEY="synthetic\'tail"`, "", true},
		{"unquoted-space", `API_KEY=synthetic\ tail`, "synthetic tail", false},
		{"unquoted-tab", "API_KEY=synthetic\\\ttail", "synthetic\ttail", false},
		{"unquoted-single-quote", `API_KEY=synthetic\'tail`, "synthetic'tail", false},
		{"double-backslash", `API_KEY="synthetic\\tail"`, `synthetic\tail`, false},
		{"double-quote", `API_KEY="synthetic\"tail"`, `synthetic"tail`, false},
		{"double-dollar", `API_KEY="synthetic\$tail"`, "synthetic$tail", false},
		{"double-backtick", "API_KEY=\"synthetic\\`tail\"", "synthetic`tail", false},
		{"single-literal", `API_KEY='synthetic\ tail'`, `synthetic\ tail`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureDir(t)
			put(t, root, "carrier", tc.body)
			got, err := Scan(context.Background(), policy(root, EnvFile, "carrier"), k)
			if tc.bad {
				if !errors.Is(err, ErrParse) || len(got) != 0 {
					t.Fatal("unsupported double-quoted escape accepted")
				}
			} else if err != nil || len(got) != 1 || got[0].Fingerprint != fp(t, k, tc.value) || got[0].Len != len(tc.value) {
				t.Fatal("supported literal escape control disagrees")
			}
		})
	}
}

func TestNamesExactAdmission(t *testing.T) {
	k := key(t, "scan")
	for _, name := range []string{"api_key", "API_KEY_SUFFIX", "API_KE"} {
		got, err := parseCarrier([]byte(name+"=synthetic\n"), Rule{Kind: EnvFile, Names: []string{"API_KEY"}}, "carrier", k)
		if err != nil || len(got) != 0 {
			t.Fatal("name double admitted")
		}
	}
	got, err := parseCarrier([]byte("API_KEY=synthetic\n"), Rule{Kind: EnvFile, Names: []string{"API_KEY"}}, "carrier", k)
	if err != nil || len(got) != 1 {
		t.Fatal("exact name control refused")
	}
}

func TestFingerprintLastByte(t *testing.T) {
	k := key(t, "scan")
	base := "kfp1:scan:aaaaaaaaaaaaaaaa"
	for _, last := range []string{"b", "7"} {
		got, err := Compare(k, []Finding{{Path: "file", Name: "API_KEY", Fingerprint: base[:len(base)-1] + last}}, []KnownCarrier{{Path: "file", Name: "API_KEY", Fingerprint: base}})
		if err != nil || len(got) != 1 || got[0].Verdict != Stale {
			t.Fatal("fingerprint suffix ignored")
		}
	}
}

func TestMalformedPairRejected(t *testing.T) {
	k := key(t, "scan")
	for _, bad := range []string{strings.Repeat("a", 64), "kfp1:scan:aaaaaaaaaaaaaaa!", ""} {
		got, err := Compare(k, []Finding{{Path: "file", Name: "API_KEY", Fingerprint: bad}}, []KnownCarrier{{Path: "file", Name: "API_KEY", Fingerprint: bad}})
		if !errors.Is(err, ErrFingerprint) || len(got) != 0 {
			t.Fatal("malformed pair admitted")
		}
	}
}

func TestConsistentlyForeignKeyRejected(t *testing.T) {
	expected := key(t, "scan")
	foreign := key(t, "foreign")
	f := fp(t, foreign, "synthetic")
	got, err := Compare(expected, []Finding{{Path: "file", Name: "API_KEY", Fingerprint: f}}, []KnownCarrier{{Path: "file", Name: "API_KEY", Fingerprint: f}})
	if !errors.Is(err, ErrFingerprint) || len(got) != 0 {
		t.Fatal("consistently foreign tenant admitted")
	}
}

func TestInvalidScanKeyOnEmptyRoot(t *testing.T) {
	root := fixtureDir(t)
	p := policy(root, EnvFile, "*.env")
	for _, k := range []fingerprint.Key{{}, key(t, "wiped")} {
		k.Wipe()
		got, err := Scan(context.Background(), p, k)
		if !errors.Is(err, ErrFingerprint) || len(got) != 0 {
			t.Fatal("invalid key on empty inventory admitted")
		}
	}
	if got, err := Scan(context.Background(), p, key(t, "scan")); err != nil || len(got) != 0 {
		t.Fatal("empty inventory control refused")
	}
}

func TestJSONStructuralDuplicatesAndKeyLimit(t *testing.T) {
	k := key(t, "scan")
	for _, body := range []string{
		`{"mcpServers":{"a":{"env":{"API_KEY":"synthetic"},"env":{"OTHER":"synthetic"}}}}`,
		`{"mcpServers":{"a":{"env":{"API_KEY":"synthetic"}}},"mcpServers":{}}`,
		`{"mcpServers":{"` + strings.Repeat("A", 257) + `":{"env":{"API_KEY":"synthetic"}}}}`,
	} {
		got, err := parseCarrier([]byte(body), Rule{Kind: MCPConfig, Names: []string{"API_KEY"}}, "carrier", k)
		if !errors.Is(err, ErrParse) || len(got) != 0 {
			t.Fatal("invalid JSON structure admitted")
		}
	}
	got, err := parseCarrier([]byte(`{"mcpServers":{"a":{"env":{"`+strings.Repeat("A", 256)+`":"synthetic","API_KEY":"synthetic"}}}}`), Rule{Kind: MCPConfig, Names: []string{"API_KEY"}}, "carrier", k)
	if err != nil || len(got) != 1 {
		t.Fatal("key length control refused")
	}
}

func TestControlPathsRejected(t *testing.T) {
	root := fixtureDir(t)
	k := key(t, "scan")
	for _, path := range []string{"carrier\n", "carrier\t", "carrier\x7f", "carrier\u0085"} {
		put(t, root, path, "API_KEY=synthetic")
		for _, pattern := range []string{path, "*"} {
			got, err := Scan(context.Background(), policy(root, EnvFile, pattern), k)
			if err == nil || len(got) != 0 {
				t.Fatal("control path admitted by scan")
			}
		}
		got, err := Compare(k, []Finding{{Path: path, Name: "API_KEY", Fingerprint: fp(t, k, "synthetic")}}, nil)
		if err == nil || len(got) != 0 {
			t.Fatal("control path admitted by comparison")
		}
	}
}

func TestCompareKeyRequired(t *testing.T) {
	for _, k := range []fingerprint.Key{{}, key(t, "wiped")} {
		k.Wipe()
		if got, err := Compare(k, nil, nil); !errors.Is(err, ErrFingerprint) || len(got) != 0 {
			t.Fatal("invalid comparison key admitted")
		}
	}
	if got, err := Compare(key(t, "scan"), nil, nil); err != nil || len(got) != 0 {
		t.Fatal("empty comparison control refused")
	}
}

func TestInvalidUTF8Paths(t *testing.T) {
	k := key(t, "scan")
	path := "carrier\xff"
	if got, err := Scan(context.Background(), policy(fixtureDir(t), EnvFile, path), k); !errors.Is(err, ErrPolicy) || len(got) != 0 {
		t.Fatal("invalid UTF-8 policy path admitted")
	}
	if got, err := Compare(k, []Finding{{Path: path, Name: "API_KEY", Fingerprint: fp(t, k, "synthetic")}}, nil); err == nil || len(got) != 0 {
		t.Fatal("invalid UTF-8 metadata admitted")
	}
}

func TestPolicyAdmissionBounds(t *testing.T) {
	base := policy(fixtureDir(t), EnvFile, "carrier")
	for _, tc := range []struct {
		name   string
		change func(*Policy)
	}{
		{"root-slash", func(p *Policy) { p.Root = "/" }},
		{"root-relative", func(p *Policy) { p.Root = "relative" }},
		{"files-over-limit", func(p *Policy) { p.MaxFiles = 4097 }},
		{"owners-over-limit", func(p *Policy) { p.TrustedUIDs = make([]uint32, 33) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.change(&p)
			if !errors.Is(validatePolicy(p), ErrPolicy) {
				t.Fatal("invalid policy admitted")
			}
			if got, err := Scan(context.Background(), p, key(t, "scan")); !errors.Is(err, ErrPolicy) || len(got) != 0 {
				t.Fatal("invalid scan policy admitted")
			}
		})
	}
	base.MaxFiles = 4096
	base.TrustedUIDs = make([]uint32, 32)
	if err := validatePolicy(base); err != nil {
		t.Fatal("policy boundary control refused")
	}
}

func TestTenantKeyPrefixRejected(t *testing.T) {
	expected := key(t, "scan")
	good := fp(t, expected, "synthetic")
	bad := fp(t, key(t, "scan2"), "synthetic")
	f := Finding{Path: "carrier", Name: "API_KEY", Fingerprint: good}
	k := KnownCarrier{Path: "carrier", Name: "API_KEY", Fingerprint: good, Active: true}
	for _, name := range []string{"finding", "known", "both", "known-only"} {
		t.Run(name, func(t *testing.T) {
			findings := []Finding{f}
			known := []KnownCarrier{k}
			if name == "finding" || name == "both" {
				findings[0].Fingerprint = bad
			}
			if name == "known" || name == "both" || name == "known-only" {
				known[0].Fingerprint = bad
			}
			if name == "known-only" {
				findings = nil
			}
			got, err := Compare(expected, findings, known)
			if !errors.Is(err, ErrFingerprint) || len(got) != 0 {
				t.Fatal("tenant key prefix admitted")
			}
		})
	}
	got, err := Compare(expected, []Finding{f}, []KnownCarrier{k})
	if err != nil || len(got) != 1 || got[0].Verdict != Match {
		t.Fatal("exact tenant key control refused")
	}
}
