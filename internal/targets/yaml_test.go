//go:build unix

package targets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func TestYAMLParseErrorNeverLeaks(t *testing.T) {
	c := canary.New()
	if !c.In("known leak " + c.Value(1)) {
		t.Fatal("canary detector positive control failed")
	}
	// A parser diagnostic for an unresolved alias includes the alias name.
	// Treat even names, comments and neighbouring scalars as value-zone data.
	data := []byte("slot: *" + c.Value(1) + "\n")
	v, found, err := readYAMLScalar(data, "slot")
	defer v.Wipe()
	if err == nil || found {
		t.Fatal("malformed YAML was accepted")
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if c.In(fmt.Sprintf("%s %+v %#v", e, e, e)) {
			t.Fatal("YAML parser diagnostic leaked canary")
		}
	}
}

func TestYAMLExactStringScalar(t *testing.T) {
	c := canary.New()
	for _, quoted := range []string{c.Value(1), "'" + c.Value(1) + "'", `"` + c.Value(1) + `"`} {
		data := []byte("mcp_servers:\n  service-one:\n    env:\n      ACCESS_KEY: " + quoted + "\nother: [1, true, null]\n")
		before := bytes.Clone(data)
		v, found, err := readYAMLScalar(data, "mcp_servers.service-one.env.ACCESS_KEY")
		if err != nil || !found {
			t.Fatal("exact string scalar refused")
		}
		good := false
		secret.Expose(v, func(b []byte) { good = bytes.Equal(b, []byte(c.Value(1))) })
		v.Wipe()
		if !good || !bytes.Equal(data, before) {
			t.Fatal("scalar differed or input changed")
		}
	}
	v, found, err := readYAMLScalar([]byte("other: value\n"), "missing.key")
	defer v.Wipe()
	if err != nil || found {
		t.Fatal("missing exact path is not absent")
	}
}

func TestYAMLRejectAmbiguityAndLimits(t *testing.T) {
	cases := map[string]string{
		"duplicate":              "slot: first\nslot: second\n",
		"nested-duplicate":       "slot: ok\nother: {key: first, key: second}\n",
		"anchor":                 "other: &shared ok\nslot: *shared\n",
		"unused-anchor":          "other: &shared ok\nslot: ok\n",
		"merge":                  "slot: ok\nother: {<<: {key: value}}\n",
		"custom-tag":             "slot: !custom value\n",
		"explicit-tag":           "slot: !!str value\n",
		"complex-key":            "? [a, b]\n: value\nslot: ok\n",
		"numeric-key":            "1: value\nslot: ok\n",
		"document-stream":        "slot: first\n---\nslot: second\n",
		"trailing-broken-stream": "slot: ok\n---\n[\n",
		"number":                 "slot: 123\n",
		"boolean":                "slot: true\n",
		"yaml-1.1-boolean":       "slot: YES\n",
		"yaml-1.1-on":            "slot: on\n",
		"null":                   "slot: null\n",
		"sequence":               "slot: [a, b]\n",
		"mapping":                "slot: {key: value}\n",
		"root-sequence":          "- slot: value\n",
		"root-scalar":            "plain\n",
		"empty":                  "",
		"oversize":               "slot: " + strings.Repeat("x", maxYAMLBytes),
		"depth":                  "slot: ok\nother: " + strings.Repeat("[", maxYAMLDepth+1) + "null" + strings.Repeat("]", maxYAMLDepth+1),
		"nodes":                  "slot: ok\nother: [" + strings.Repeat("x,", maxYAMLNodes) + "x]",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			v, found, err := readYAMLScalar([]byte(data), "slot")
			defer v.Wipe()
			if err == nil || found {
				t.Fatal("unsafe or unsupported YAML accepted")
			}
		})
	}
	for _, field := range []string{"", ".slot", "slot.", "a..slot", "slot[0]", strings.Repeat("a.", 16) + "slot"} {
		v, found, err := readYAMLScalar([]byte("slot: ok\n"), field)
		v.Wipe()
		if err == nil || found {
			t.Fatal("unsupported field selector accepted")
		}
	}
}

func TestYAMLObserveReadOnlyAndWriteDenied(t *testing.T) {
	c := canary.New()
	k := observeKey(t)
	defer k.Wipe()
	tg := observeTarget(t, "service:\n  API_KEY: '"+c.Value(1)+"'\n")
	tg.Kind, tg.Field = runnerproto.TargetYAMLScalar, "service.API_KEY"
	if err := os.WriteFile(tg.Path+".bak", []byte("disposable backup"), 0o400); err != nil {
		t.Fatal("create backup fixture")
	}
	paths := []string{tg.Path, tg.Path + ".bak"}
	before := make([]os.FileInfo, len(paths))
	bodies := make([][]byte, len(paths))
	for i, p := range paths {
		var err error
		before[i], err = os.Stat(p)
		if err != nil {
			t.Fatal("stat fixture")
		}
		bodies[i], err = os.ReadFile(p) //nolint:gosec // G304: test-owned temporary fixture
		if err != nil {
			t.Fatal("read fixture")
		}
	}
	owner, exists, err := OwnerOf(tg, nil, nil)
	if err != nil || !exists {
		t.Fatal("YAML owner read refused")
	}
	got, found, err := Observe(tg, owner, nil, nil, k)
	v := secret.New([]byte(c.Value(1)))
	want, _ := computeFingerprint(k, v)
	v.Wipe()
	if err != nil || !found || !SameFingerprint(got, want) || SameFingerprint(got, want+"x") {
		t.Fatal("YAML fingerprint comparison failed")
	}
	tg.Field = "service.absent"
	if _, found, err := Observe(tg, owner, nil, nil, k); err != nil || found {
		t.Fatal("missing YAML field was found")
	}
	tg.Field = "service.API_KEY"
	v = secret.New([]byte(c.Value(2)))
	defer v.Wipe()
	if _, err := Write(tg, v, nil, nil, k); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "read-only") {
		t.Fatal("YAML write was not explicitly refused")
	}
	for i, p := range paths {
		after, err := os.Stat(p)
		body, readErr := os.ReadFile(p) //nolint:gosec // G304: test-owned temporary fixture
		if err != nil || readErr != nil || !bytes.Equal(body, bodies[i]) || !os.SameFile(before[i], after) || before[i].Mode() != after.Mode() || !before[i].ModTime().Equal(after.ModTime()) {
			t.Fatal("read or refused write changed carrier or backup")
		}
		old, now := before[i].Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
		if old.Uid != now.Uid || old.Gid != now.Gid {
			t.Fatal("carrier ownership changed")
		}
	}
	link := filepath.Join(filepath.Dir(tg.Path), "linked.yaml")
	if err := os.Symlink(tg.Path, link); err != nil {
		t.Fatal("create symlink fixture")
	}
	tg.Path = link
	if _, _, err := Observe(tg, owner, nil, nil, k); err == nil {
		t.Fatal("YAML symlink was read")
	}
}
