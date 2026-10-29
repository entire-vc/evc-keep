//go:build unix

package targets_test

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

const plistHead = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`

// A CDATA section that mentions an EnvironmentVariables dict: a text search finds
// it before the real key, so the value must not end up in ProgramArguments.
func TestTargetsAttack_PlistDecoyInCDATA(t *testing.T) {
	for name, decoy := range map[string]string{
		"cdata": `<![CDATA[<key>EnvironmentVariables</key><dict></dict>]]>`,
	} {
		t.Run(name, func(t *testing.T) {
			d := dir(t)
			p := filepath.Join(d, "x.plist")
			orig := plistHead + "\t<key>Label</key>\n\t<string>x</string>\n\t<key>ProgramArguments</key>\n\t<array><string>/bin/true</string><string>" + decoy + "</string></array>\n\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>A</key>\n\t\t<string>1</string>\n\t</dict>\n</dict>\n</plist>\n"
			ok(t, os.WriteFile(p, []byte(orig), 0o600))
			_, err := targets.Write(tgt(runnerproto.TargetLaunchdEnv, p, "NAME"), secret.New([]byte(canary)), nil, nil, fpKey(t))
			b, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
			if err != nil {
				t.Logf("refused: %v", err)
				if string(b) != orig {
					t.Errorf("refused but changed")
				}
				return
			}
			// An independent reading of the written plist: a token walk that knows
			// nothing about the writer's own locator. (plutil, where it exists,
			// says the same; the walk runs everywhere, alpine CI included.)
			top := plistTopLevelText(t, b)
			if slices.ContainsFunc(top["ProgramArguments"], func(s string) bool { return strings.Contains(s, canary) }) {
				t.Errorf("VALUE LANDED IN ProgramArguments (argv of the job) while Write returned success")
			}
			env := top["EnvironmentVariables"]
			i := slices.Index(env, "NAME")
			if i < 0 || i+1 >= len(env) || env[i+1] != canary {
				t.Errorf("value not in the real EnvironmentVariables dict")
			}
			if _, lerr := exec.LookPath("plutil"); lerr == nil {
				out, perr := exec.Command("plutil", "-extract", "ProgramArguments", "json", "-o", "-", p).CombinedOutput() //nolint:gosec // G204: our own tempdir path
				if perr != nil || strings.Contains(string(out), canary) {
					t.Errorf("plutil: ProgramArguments holds the value or does not parse (err=%v)", perr)
				}
			}
		})
	}
}

// R-POL-4 / §2.3: an existing target that anyone, or an agent group, can write
// may have been planted with content; Write would carry that content, byte for
// byte, into a fresh file agents can no longer touch.
func TestTargetsAttack_ExistingTargetWritableByOthersRefused(t *testing.T) {
	gid := int64(os.Getegid())
	for _, c := range []struct {
		mode  os.FileMode
		gids  []int64
		label string
	}{{0o666, nil, "world-writable"}, {0o662, nil, "world-writable (other w)"}, {0o660, []int64{gid}, "agent-group-writable"}, {0o620, []int64{gid}, "agent-group-writable (no read)"}} {
		t.Run(c.label, func(t *testing.T) {
			d := dir(t)
			p := filepath.Join(d, "svc.env")
			ok(t, os.WriteFile(p, []byte("PLANTED=by-agent\n"), 0o600))
			ok(t, os.Chmod(p, c.mode))
			_, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, "NAME"), secret.New([]byte("v")), nil, c.gids, fpKey(t))
			b, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
			if err == nil {
				t.Errorf("existing target with mode %o accepted as base; content now %s", c.mode, redact(b))
			}
		})
	}
}

func TestTargetsAttack_JSONReplacesObjectWithString(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "mcp.json")
	orig := `{"mcpServers":{"a":{"command":"x","env":{"K":"v"}}}}`
	ok(t, os.WriteFile(p, []byte(orig), 0o600))
	_, err := targets.Write(tgt(runnerproto.TargetMCPConfig, p, "mcpServers.a.env"), secret.New([]byte("v")), nil, nil, fpKey(t))
	b, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
	t.Logf("err=%v file=%s", err, redact(b))
	if err == nil {
		t.Errorf("existing object replaced by secret string")
	}
}

// plistTopLevelText maps each key of the plist's top-level dict to the text of
// every element inside its value, in document order (for a dict: key, value,
// key, value...). It is a plain token walk, deliberately not the writer's.
func plistTopLevelText(t *testing.T, plist []byte) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	dec := xml.NewDecoder(bytes.NewReader(plist))
	var stack []string
	var cur, text string
	haveKey := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("written plist does not parse: %v", err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			stack = append(stack, e.Name.Local)
			text = ""
		case xml.CharData:
			text += string(e)
		case xml.EndElement:
			n := len(stack)
			switch {
			case n == 3 && stack[2] == "key":
				cur, haveKey = text, true
			case n > 3 && haveKey && (stack[n-1] == "string" || stack[n-1] == "key"):
				out[cur] = append(out[cur], text)
			case n == 3 && haveKey && stack[2] == "string":
				out[cur] = append(out[cur], text)
			}
			text = ""
			stack = stack[:n-1]
		}
	}
	return out
}
