package main

// A value a carrier cannot hold byte for byte is refused by the runner. The
// refusal is the runner's residual oracle on the value (threat model 7.2): it
// is accepted only while the one thing that leaves the host is the closed
// class policy_denied. This test drives such values through the real
// binaries, for the env-file, json-path and launchd-env carriers, and checks
// that no surface carries the runner's refusal text or the value, that the
// answers do not tell the refusals apart, and that the carrier is untouched.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

const e2ePlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>vc.entire.e2e</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>OTHER</key>
		<string>untouched</string>
	</dict>
</dict>
</plist>
`

const e2eMCP = `{"mcpServers":{"other":{"command":"x"}}}` + "\n"

// The runner's own diagnostics for a value it will not write. They stay on
// the host; none may appear in an answer, the journal or the server output.
var e2eRefusalTexts = []string{
	"not valid UTF-8", "plist string", "env-file line", "cannot be represented",
	"JSON string", "byte for byte", "cannot appear",
}

func TestKeepDeployRefusalByValueIsOnlyPolicyDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("builds three binaries and starts a server")
	}
	w := newDeployWorld(t)
	c := canary.New()

	cases := []struct {
		kind, file, field, initial string
		bad                        []string // each must be refused
	}{
		{"env-file", "refuse.env", "STRIPE_API_KEY", "", []string{"nul\x00one", "line\none-longer", "l\r"}},
		{"mcp-config", "refuse.json", e2eJSONField, e2eMCP, []string{"bad\xff\xfeutf8", "\x80", "e\xe2\x82", "s\xed\xa0\x80", "o\xc0\xafvl"}},
		{"launchd-env", "refuse.plist", e2ePlistField, e2ePlist, []string{"nul\x00one", "ctl\x01one", "bad\xff\xfeutf8"}},
	}
	n := 0
	for _, tc := range cases {
		path := filepath.Join(w.targetDir, tc.file)
		if tc.initial != "" {
			if err := os.WriteFile(path, []byte(tc.initial), 0o600); err != nil {
				t.Fatal("write carrier fixture")
			}
		}
		// Positive control: a clean value reaches the carrier, so a refusal
		// below is the value's doing and the path under test is live.
		n++
		w.seedKind("ok-"+itoa(n), "dev", c.Value(n), w.targetDir, tc.kind)
		okReq := "e2e-rok-" + uuid.NewString()[:8]
		if code, out, errOut := w.deployKind(tc.kind, "ok-"+itoa(n), path, tc.field, okReq); code != 0 {
			t.Fatalf("%s: clean value was not deployed (exit %d): %s %s", tc.kind, code, out, errOut)
		}
		written, err := os.ReadFile(path) //nolint:gosec // G304: test-owned path
		if err != nil || !c.In(string(written)) {
			t.Fatalf("%s: carrier does not hold the clean value (positive control)", tc.kind)
		}
		before := string(written)
		entries := func() string {
			des, err := os.ReadDir(w.targetDir)
			if err != nil {
				t.Fatal("list carrier directory")
			}
			var names []string
			for _, de := range des {
				names = append(names, de.Name())
			}
			return strings.Join(names, ",")
		}
		dirBefore := entries()

		type answer struct{ cli, status, audit string }
		var answers []answer
		for i, bad := range tc.bad {
			n++
			name := "refuse-" + itoa(n)
			w.seedKind(name, "dev", bad+c.Value(n), w.targetDir, tc.kind)
			r := "e2e-ref-" + uuid.NewString()[:8]
			code, out, errOut := w.deployKind(tc.kind, name, path, tc.field, r)
			if code != 1 {
				t.Fatalf("%s value %d: exit %d, want a refusal: %s %s", tc.kind, i, code, out, errOut)
			}
			status := w.status(r)
			audit := w.auditProjection(r)
			for surface, got := range map[string][]string{"cli": jsonClasses(out), "status": jsonClasses(status), "audit": auditClasses(audit)} {
				if len(got) != 1 || got[0] != "policy_denied" {
					t.Errorf("%s value %d: %s error class is %q, want exactly [policy_denied]", tc.kind, i, surface, got)
				}
			}
			for surface, s := range map[string]string{"cli": out + errOut, "status": status, "audit": audit} {
				if c.In(s) {
					t.Errorf("%s value %d: value canary found in %s", tc.kind, i, surface)
				}
				for _, txt := range e2eRefusalTexts {
					if strings.Contains(s, txt) {
						t.Errorf("%s value %d: runner refusal text %q reached %s", tc.kind, i, txt, surface)
					}
				}
			}
			if got, _ := os.ReadFile(path); string(got) != before { //nolint:gosec // G304: test-owned path
				t.Fatalf("%s value %d: the carrier changed after a refusal", tc.kind, i)
			}
			if entries() != dirBefore {
				t.Fatalf("%s value %d: a refusal left files in the carrier directory", tc.kind, i)
			}
			norm := func(s string) string {
				s = e2eNormalize(s, r)
				return strings.ReplaceAll(s, name, "NAME")
			}
			answers = append(answers, answer{norm(out + errOut), norm(status), norm(audit)})
		}
		// Reference: a policy_denied that is not about the value (a field the
		// host policy does not admit) must read exactly like a value refusal.
		n++
		refName := "refuse-" + itoa(n)
		w.seedKind(refName, "dev", c.Value(n), w.targetDir, tc.kind)
		refReq := "e2e-ref-" + uuid.NewString()[:8]
		otherField := strings.Replace(tc.field, "API_KEY", "OTHER_KEY", 1)
		if otherField == tc.field {
			otherField = tc.field + "_X"
		}
		code, refOut, refErr := w.deployKind(tc.kind, refName, path, otherField, refReq)
		if code != 1 {
			t.Fatalf("%s: field outside the host policy: exit %d: %s %s", tc.kind, code, refOut, refErr)
		}
		normRef := func(s string) string {
			s = e2eNormalize(s, refReq)
			return strings.ReplaceAll(strings.ReplaceAll(s, refName, "NAME"), otherField, tc.field)
		}
		ref := answer{normRef(refOut + refErr), normRef(w.status(refReq)), normRef(w.auditProjection(refReq))}
		if len(answers) > 0 && answers[0] != ref {
			t.Fatalf("%s: a refusal by value reads differently from a refusal by host policy:\n%+v\n%+v", tc.kind, answers[0], ref)
		}
		for i := 1; i < len(answers); i++ {
			if answers[i] != answers[0] {
				t.Fatalf("%s: refusal %d differs from refusal 0:\n%+v\n%+v", tc.kind, i, answers[i], answers[0])
			}
		}
	}

	// Nothing on the server side or in the journal carries the runner's
	// refusal text or the value, in any of the six encodings.
	if !c.In("x"+c.Value(1)+"y") || !c.In("x"+c.Value(1)) {
		t.Fatal("canary detector is blind")
	}
	surfaces := map[string]string{"server output": w.serverOut.String(), "audit": w.auditText(), "runner output": w.runnerOut.String(), "enroll output": w.enrollOut.String()}
	for name, s := range surfaces {
		if c.In(s) {
			t.Errorf("value canary found in %s", name)
		}
		for _, txt := range e2eRefusalTexts {
			if strings.Contains(s, txt) {
				t.Errorf("runner refusal text %q reached %s", txt, name)
			}
		}
	}
}

// jsonClasses returns every error_class value in a JSON answer, at any depth.
// An answer that is not JSON yields a marker, so it cannot pass as clean.
func jsonClasses(answer string) []string {
	var v any
	if err := json.Unmarshal([]byte(answer), &v); err != nil {
		return []string{"<not json>"}
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				if k == "error_class" {
					out = append(out, fmt.Sprint(e))
					continue
				}
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// auditClasses returns the non-empty result_error_class of each projected
// audit row (the last field of the projection).
func auditClasses(projection string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(projection), "\n") {
		if i := strings.LastIndex(line, "|"); i >= 0 && line[i+1:] != "" {
			out = append(out, line[i+1:])
		}
	}
	return out
}
