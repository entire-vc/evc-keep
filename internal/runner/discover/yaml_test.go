package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestYAMLDiscoveryExactFieldsAndRegistryMatch(t *testing.T) {
	c := canary.New()
	if !c.In(c.Value(1)) {
		t.Fatal("canary positive control failed")
	}
	root := fixtureDir(t)
	const field = "mcp_servers.bridge.env.API_KEY"
	put(t, root, "config.yaml", "mcp_servers:\n  bridge:\n    env:\n      API_KEY: '"+c.Value(1)+"'\nother:\n  API_KEY: '"+c.Value(2)+"'\n")
	p := policy(root, YAMLScalar, "*.yaml")
	p.Rules[0].Names = []string{field}
	k := key(t, "yamltenant")
	before, _ := os.ReadFile(filepath.Join(root, "config.yaml")) //nolint:gosec // G304: test-owned temporary fixture
	findings, err := Scan(context.Background(), p, k)
	if err != nil || len(findings) != 1 || findings[0].Name != field || findings[0].Len != len(c.Value(1)) || findings[0].Fingerprint != fp(t, k, c.Value(1)) {
		t.Fatal("exact YAML finding failed")
	}
	known := []KnownCarrier{{Path: "config.yaml", Name: field, Fingerprint: findings[0].Fingerprint, Active: true}}
	compared, err := Compare(k, findings, known)
	if err != nil || len(compared) != 1 || compared[0].Verdict != Match {
		t.Fatal("registered YAML field was not matched")
	}
	known[0].Fingerprint = fp(t, k, c.Value(2))
	compared, err = Compare(k, findings, known)
	if err != nil || len(compared) != 1 || compared[0].Verdict != Stale {
		t.Fatal("different YAML scalar was not stale")
	}
	known[0].Name = "other.API_KEY"
	compared, err = Compare(k, findings, known)
	if err != nil || len(compared) != 2 || compared[0].Verdict != Sprawl || compared[1].Verdict != UnknownFind {
		t.Fatal("different exact field collided with registered field")
	}
	for _, surface := range []any{findings, compared} {
		b, err := json.Marshal(surface)
		if err != nil || c.In(string(b)) || c.In(fmt.Sprintf("%+v", surface)) {
			t.Fatal("YAML discovery leaked canary")
		}
	}
	after, err := os.ReadFile(filepath.Join(root, "config.yaml")) //nolint:gosec // G304: test-owned temporary fixture
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("discovery modified YAML")
	}
}

func TestYAMLDiscoveryRefusesUnsafeDocumentsAndPaths(t *testing.T) {
	c := canary.New()
	root := fixtureDir(t)
	p := policy(root, YAMLScalar, "config.yaml")
	p.Rules[0].Names = []string{"service.API_KEY"}
	k := key(t, "yamltenant")
	for _, body := range []string{
		"service:\n  API_KEY: *" + c.Value(1) + "\n",
		"service: {API_KEY: one, API_KEY: two}\n",
		"service: {API_KEY: true}\n",
		"service: {API_KEY: &anchor text}\n",
	} {
		put(t, root, "config.yaml", body)
		out, err := Scan(context.Background(), p, k)
		if !errors.Is(err, ErrParse) || len(out) != 0 || c.In(fmt.Sprintf("%+v", err)) {
			t.Fatal("unsafe YAML was accepted or leaked parser detail")
		}
	}
	put(t, root, "config.yaml", "service: {API_KEY: value}\n")
	if out, err := Scan(context.Background(), p, k); err != nil || len(out) != 1 {
		t.Fatal("positive control YAML refused")
	}
	p.Rules[0].Glob = "../config.yaml"
	if _, err := Scan(context.Background(), p, k); !errors.Is(err, ErrPolicy) {
		t.Fatal("path escape accepted")
	}
	p.Rules[0].Glob = "link.yaml"
	if err := os.Symlink(filepath.Join(root, "config.yaml"), filepath.Join(root, "link.yaml")); err != nil {
		t.Fatal("create symlink fixture")
	}
	if _, err := Scan(context.Background(), p, k); !errors.Is(err, ErrRead) {
		t.Fatal("YAML symlink accepted")
	}
	p.Rules[0].Glob = "config.yaml"
	p.MaxBytes = 4
	if _, err := Scan(context.Background(), p, k); !errors.Is(err, ErrSize) {
		t.Fatal("oversize YAML accepted")
	}
}
