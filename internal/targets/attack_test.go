//go:build unix

package targets_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func fpKey(t *testing.T) fingerprint.Key {
	k, err := fingerprint.NewKey("k1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ok fails the test on an error from a setup call whose failure would make the
// scenario meaningless.
func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// redact describes content for a test message by length and a short digest:
// the files these tests build hold neighbouring "secrets" (fixtures and the
// canary), and a CI log outlives the run.
func redact[T ~string | ~[]byte](x T) string {
	k, err := fingerprint.GenerateKey("redact") // random per call: a fixed key would make the digest a plain hash a log reader can grind
	if err != nil {
		return fmt.Sprintf("%d bytes", len(x))
	}
	fp, err := fingerprint.Compute(k, secret.New([]byte(x)))
	if err != nil {
		return fmt.Sprintf("%d bytes", len(x))
	}
	return fmt.Sprintf("%d bytes, %s", len(x), fp)
}

func dir(t *testing.T) string {
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ok(t, os.Chown(d, -1, os.Getegid())) // see realDir in testutil_test.go
	sub := filepath.Join(d, "w")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	return sub
}

func tgt(kind runnerproto.TargetKind, path, field string) runnerproto.Target {
	return runnerproto.Target{Kind: kind, Path: path, Field: field, Mode: 0o600, UID: int64(os.Geteuid()), GID: int64(os.Getegid())}
}

const canary = "CANARY-7f3a91c2e8b4d6a05f1e"

func TestTargetsAttack_EnvFileNeighboursAndPrefixes(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "svc.env")
	orig := "# NAME=commented\nexport NAME2=n2\nNAME_X=nx\nNAMEX=x\n NAME=indented\r\nOTHER=" + canary + "\n"
	ok(t, os.WriteFile(p, []byte(orig), 0o600))
	fp, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, "NAME"), secret.New([]byte("newvalue")), nil, nil, fpKey(t))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
	want := orig + "NAME=newvalue\n"
	if string(got) != want {
		t.Errorf("neighbours changed or wrong line replaced:\n got %s\nwant %s", redact(got), redact(want))
	}
	exp, _ := fingerprint.Compute(fpKey(t), secret.New([]byte("newvalue")))
	if fp != exp {
		t.Errorf("fingerprint %q != independent %q", fp, exp)
	}
}

func TestTargetsAttack_EnvFileNoTrailingNewlineKeepsNeighbourBytes(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "svc.env")
	ok(t, os.WriteFile(p, []byte("A=1\nNAME=old"), 0o600))
	if _, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, "NAME"), secret.New([]byte("v")), nil, nil, fpKey(t)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
	t.Logf("result: %s", redact(got))
	if string(got) != "A=1\nNAME=v\n" {
		t.Errorf("got %s", redact(got))
	}
}

func TestTargetsAttack_EnvFileHostileValues(t *testing.T) {
	for name, v := range map[string]string{
		"lf": "a\nEVIL=1", "cr": "a\rEVIL=1", "nul": "a\x00b", "crlf": "a\r\nEVIL=1", "vt": "a\vb", "ff": "a\fb", "u2028": "a EVIL=1", "nel": "a\u0085EVIL=1",
	} {
		t.Run(name, func(t *testing.T) {
			d := dir(t)
			p := filepath.Join(d, "svc.env")
			ok(t, os.WriteFile(p, []byte("A=1\n"), 0o600))
			_, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, "NAME"), secret.New([]byte(v)), nil, nil, fpKey(t))
			got, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
			if err == nil {
				// accepted: must not have produced an extra logical line
				lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
				if len(lines) != 2 {
					t.Errorf("value injected extra line(s): %s", redact(got))
				}
				t.Logf("accepted, file=%s", redact(got))
			} else if string(got) != "A=1\n" {
				t.Errorf("refused but file changed: %s", redact(got))
			}
		})
	}
}

func TestTargetsAttack_SymlinkVariants(t *testing.T) {
	d := dir(t)
	outside := filepath.Join(d, "outside")
	ok(t, os.Mkdir(outside, 0o700))
	victim := filepath.Join(outside, "victim.env")
	ok(t, os.WriteFile(victim, []byte("KEEP="+canary+"\n"), 0o600))
	// symlink in middle
	ok(t, os.Symlink(outside, filepath.Join(d, "link")))
	// symlink on the file
	real := filepath.Join(d, "real")
	ok(t, os.Mkdir(real, 0o700))
	ok(t, os.Symlink(victim, filepath.Join(real, "svc.env")))
	for name, p := range map[string]string{
		"mid": filepath.Join(d, "link", "victim.env"), "leaf": filepath.Join(real, "svc.env"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, "NAME"), secret.New([]byte("zzz")), nil, nil, fpKey(t))
			if err == nil {
				t.Fatal("symlinked path accepted")
			}
			b, _ := os.ReadFile(victim) //nolint:gosec // G304: test-controlled path
			if string(b) != "KEEP="+canary+"\n" {
				t.Errorf("victim modified: %s", redact(b))
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("canary in error")
			}
		})
	}
}

func TestTargetsAttack_HardlinkExistingTargetToForeignFile(t *testing.T) {
	d := dir(t)
	foreign := filepath.Join(d, "other-service.env")
	ok(t, os.WriteFile(foreign, []byte("OTHER_SECRET="+canary+"\n"), 0o600))
	p := filepath.Join(d, "svc.env")
	if err := os.Link(foreign, p); err != nil {
		t.Fatal(err)
	}
	_, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, "NAME"), secret.New([]byte("v")), nil, nil, fpKey(t))
	if err == nil {
		b, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
		t.Fatalf("hardlinked existing target accepted; content now %s", redact(b))
	}
	b, _ := os.ReadFile(foreign) //nolint:gosec // G304: test-controlled path
	if string(b) != "OTHER_SECRET="+canary+"\n" {
		t.Errorf("foreign file modified: %s", redact(b))
	}
}

func TestTargetsAttack_PathGarbage(t *testing.T) {
	d := dir(t)
	for name, p := range map[string]string{
		"empty": "", "relative": "svc.env", "dotdot": d + "/../w/svc.env", "dot": d + "/./svc.env", "dslash": d + "//svc.env",
		"trailing": d + "/svc.env/", "nul": d + "/svc\x00.env", "dir": d, "root": "/", "newline": d + "/a\nb", "long": d + "/" + strings.Repeat("a", 5000),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := targets.Write(tgt(runnerproto.TargetFile, p, ""), secret.New([]byte(canary)), nil, nil, fpKey(t))
			if err == nil {
				t.Errorf("accepted path %q", p)
				return
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("canary in error")
			}
		})
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 0 {
		t.Errorf("leftovers after refusals: %v", ents)
	}
}

func TestTargetsAttack_ModesAndOwnership(t *testing.T) {
	uid, gid := int64(os.Geteuid()), int64(os.Getegid())
	d := dir(t)
	cases := map[string]struct {
		mode     uint32
		agentsUI []int64
		agentsGI []int64
	}{
		"0644": {0o644, nil, nil}, "0666": {0o666, nil, nil}, "0604": {0o604, nil, nil}, "0640-agent-gid": {0o640, nil, []int64{gid}}, "0600-agent-uid": {0o600, []int64{uid}, nil},
		"0o4755": {0o4755, nil, nil}, "0o1777": {0o1777, nil, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(d, "f-"+strings.ReplaceAll(name, "/", "_"))
			tg := tgt(runnerproto.TargetFile, p, "")
			tg.Mode = c.mode
			_, err := targets.Write(tg, secret.New([]byte(canary)), c.agentsUI, c.agentsGI, fpKey(t))
			if err == nil {
				t.Errorf("accepted %s", name)
			}
			if _, e := os.Lstat(p); e == nil {
				t.Errorf("file exists after refusal")
			}
		})
	}
}

func TestTargetsAttack_UmaskDoesNotWiden(t *testing.T) {
	d := dir(t)
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	p := filepath.Join(d, "svc")
	tg := tgt(runnerproto.TargetFile, p, "")
	tg.Mode = 0o640
	tg.GID = int64(os.Getegid())
	if _, err := targets.Write(tg, secret.New([]byte("v")), nil, nil, fpKey(t)); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 1 {
		t.Errorf("leftover temp files: %v", ents)
	}
}

func TestTargetsAttack_ExistingLooseTargetTightened(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "svc")
	ok(t, os.WriteFile(p, []byte("old"), 0o666)) //nolint:gosec // G306: the loose mode is the scenario
	ok(t, os.Chmod(p, 0o666))                    //nolint:gosec // G302: the loose mode is the scenario
	if _, err := targets.Write(tgt(runnerproto.TargetFile, p, ""), secret.New([]byte("v")), nil, nil, fpKey(t)); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode after rewrite %v", st.Mode().Perm())
	}
}

func TestTargetsAttack_FileValueVerbatimAndFingerprint(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "svc")
	v := []byte("a\x00b\nc \xff\xfe end ")
	fp, err := targets.Write(tgt(runnerproto.TargetFile, p, ""), secret.New(v), nil, nil, fpKey(t))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
	if !bytes.Equal(got, v) {
		t.Errorf("got %s", redact(got))
	}
	exp, _ := fingerprint.Compute(fpKey(t), secret.New(v))
	if fp != exp {
		t.Errorf("fp mismatch")
	}
}

func TestTargetsAttack_JSONNeighboursSemantics(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "mcp.json")
	orig := `{"mcpServers":{"a":{"command":"x","env":{"KEEP":"` + canary + `","N":12345678901234567890123}},"b":{"env":{"T":"<&>"}}},"big":1e400,"f":1.10,"u":"é😀"}`
	ok(t, os.WriteFile(p, []byte(orig), 0o600))
	if _, err := targets.Write(tgt(runnerproto.TargetMCPConfig, p, "mcpServers.a.env.TOKEN"), secret.New([]byte(`v"\`+"\n")), nil, nil, fpKey(t)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
	t.Logf("json out: %s", redact(b))
	var got, want map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	dec = json.NewDecoder(strings.NewReader(orig))
	dec.UseNumber()
	ok(t, dec.Decode(&want))
	want["mcpServers"].(map[string]any)["a"].(map[string]any)["env"].(map[string]any)["TOKEN"] = "v\"\\\n"
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if !bytes.Equal(gb, wb) {
		t.Errorf("semantic change:\n got %s\nwant %s", redact(gb), redact(wb))
	}
	if !strings.Contains(string(b), "12345678901234567890123") {
		t.Errorf("big integer altered")
	}
}

func TestTargetsAttack_JSONPathThroughNonObject(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "mcp.json")
	orig := `{"mcpServers":{"a":"str","b":[1,2],"c":null}}`
	ok(t, os.WriteFile(p, []byte(orig), 0o600))
	for _, f := range []string{"mcpServers.a.env.T", "mcpServers.b.env.T", "mcpServers.c.env.T", "mcpServers.a"} {
		_, err := targets.Write(tgt(runnerproto.TargetMCPConfig, p, f), secret.New([]byte("v")), nil, nil, fpKey(t))
		b, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
		if err == nil {
			t.Logf("%s accepted -> %s", f, redact(b))
			ok(t, os.WriteFile(p, []byte(orig), 0o600))
			continue
		}
		if string(b) != orig {
			t.Errorf("%s refused but file changed: %s", f, redact(b))
		}
	}
}

func TestTargetsAttack_JSONErrorsNeverEchoContent(t *testing.T) {
	d := dir(t)
	for name, content := range map[string]string{
		"syntax": `{"KEEP":"` + canary + `" oops}`, "trunc": `{"KEEP":"` + canary, "trailing": `{"a":1} ` + canary, "array": `["` + canary + `"]`, "badescape": `{"a":"\q` + canary + `"}`, "wrongtype": `{"mcpServers":"` + canary + `"}`, "nested-type": `{"mcpServers":{"a":{"env":"` + canary + `"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(d, name+".json")
			ok(t, os.WriteFile(p, []byte(content), 0o600))
			_, err := targets.Write(tgt(runnerproto.TargetMCPConfig, p, "mcpServers.a.env.T"), secret.New([]byte("v")), nil, nil, fpKey(t))
			if err == nil {
				t.Logf("accepted")
				return
			}
			if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), canary[:8]) {
				t.Errorf("error echoes file content: %v", err)
			}
		})
	}
}

func TestTargetsAttack_PlistInjectionAndNeighbours(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "x.plist")
	orig := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>x</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>KEEP</key>
		<string>` + canary + `</string>
	</dict>
	<key>ProgramArguments</key>
	<array><string>/bin/true</string></array>
</dict>
</plist>
`
	for name, v := range map[string]string{"markup": `</string><key>Evil</key><string>1`, "amp": "a&b<c>d", "cdata": "]]>", "quote": `"'`, "ctrl": "a\x01b", "nl": "a\nb", "unicode": "héllo😀"} {
		t.Run(name, func(t *testing.T) {
			ok(t, os.WriteFile(p, []byte(orig), 0o600))
			_, err := targets.Write(tgt(runnerproto.TargetLaunchdEnv, p, "NAME"), secret.New([]byte(v)), nil, nil, fpKey(t))
			b, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
			if err != nil {
				if string(b) != orig {
					t.Errorf("refused but changed")
				}
				return
			}
			if strings.Contains(string(b), "<key>Evil</key>") {
				t.Errorf("plist injection: %s", redact(b))
			}
			if !strings.Contains(string(b), "<key>KEEP</key>\n\t\t<string>"+canary+"</string>") || !strings.Contains(string(b), "<key>ProgramArguments</key>") {
				t.Errorf("neighbours changed: %s", redact(b))
			}
		})
	}
}

func TestTargetsAttack_ConcurrentWritersNoTornFile(t *testing.T) {
	d := dir(t)
	p := filepath.Join(d, "svc")
	a, b := strings.Repeat("A", 200000), strings.Repeat("B", 200000)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		v := a
		if i%2 == 1 {
			v = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = targets.Write(tgt(runnerproto.TargetFile, p, ""), secret.New([]byte(v)), nil, nil, fpKey(t)) // contention: an error is fine, a torn file is not
		}()
	}
	wg.Wait()
	got, _ := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
	if string(got) != a && string(got) != b {
		t.Errorf("torn file, len %d", len(got))
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 1 {
		t.Errorf("leftovers: %v", ents)
	}
}

func TestTargetsAttack_ErrorsNeverContainValue(t *testing.T) {
	d := dir(t)
	ok(t, os.WriteFile(filepath.Join(d, "ro"), nil, 0o600))
	cases := []runnerproto.Target{
		tgt(runnerproto.TargetEnvFile, filepath.Join(d, "nodir", "x"), "NAME"),
		tgt(runnerproto.TargetLaunchdEnv, filepath.Join(d, "missing.plist"), "NAME"),
		tgt(runnerproto.TargetEnvFile, filepath.Join(d, "x"), "bad name"),
		tgt(runnerproto.TargetKind("weird"), filepath.Join(d, "x"), ""),
		tgt(runnerproto.TargetHermesConfig, filepath.Join(d, "ro"), "a..b"),
	}
	for i, tg := range cases {
		_, err := targets.Write(tg, secret.New([]byte(canary)), nil, nil, fpKey(t))
		if err == nil {
			t.Errorf("case %d accepted", i)
			continue
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("case %d: value in error: %v", i, err)
		}
		if !errors.Is(err, targets.ErrPolicy) && !errors.Is(err, targets.ErrWrite) {
			t.Errorf("case %d: unclassified error %v", i, err)
		}
	}
}
