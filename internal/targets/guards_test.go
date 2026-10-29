//go:build unix

package targets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"golang.org/x/sys/unix"
)

// show describes bytes for a failure message without printing them: a target
// holds other services' secrets next to the one under test, and a CI log
// outlives the run. Length and a short digest are enough to tell two contents
// apart; nothing here ever prints file content.
func show(b []byte) string { return fmt.Sprintf("%d bytes, digest %s", len(b), digest(b)) }

// showKey is random per test process and the same for every call in it: two
// digests in one message compare equal exactly when the bytes do, and neither
// is a plain hash a log reader could grind.
var showKey, _ = fingerprint.GenerateKey("show")

func digest(b []byte) string {
	fp, err := fingerprint.Compute(showKey, newValue(string(b)))
	if err != nil {
		return "?"
	}
	return fp
}

// envNames is the variable names of `env` output — never the values.
func envNames(env []byte) []string {
	var names []string
	for _, l := range strings.Split(string(env), "\n") {
		if name, _, ok := strings.Cut(l, "="); ok && name != "" {
			names = append(names, name)
		}
	}
	return names
}

// --- env-file ---------------------------------------------------------------

// A NUL or CR in the value cannot be carried by a line-oriented file, and each
// of the three forbidden bytes is switched off on its own by the mutation
// script, so each is exercised alone.
func TestEnvFileRejectsNULAndCRInValue(t *testing.T) {
	for name, v := range map[string]string{"nul": "a\x00b", "cr": "a\rb", "lf": "a\nb"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "app.env")
			mustWriteFile(t, path, []byte("A=1\n"), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue(v), uids, gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "value with a byte a line cannot hold")
			if got := mustReadFile(t, path); string(got) != "A=1\n" {
				t.Fatalf("file changed despite the refusal: %s", show(got))
			}
		})
	}
}

// Values that need quoting are written so a shell consumer reads them back as
// themselves, and the fingerprint attests to the value the consumer sees. The
// consumer-side proof (a real shell) is in the attack test
// TestTargetsAttack_EnvFileConsumerSeesSameValue; this is the round trip.
func TestEnvFileQuotedValuesRoundTrip(t *testing.T) {
	for name, v := range map[string]string{
		"bare":      "abc-DEF_123/+=:.,@%",
		"empty":     "",
		"space":     "a b",
		"quote":     `it's`,
		"quotes":    `'x'`,
		"dollar":    "$HOME`id`;#",
		"backslash": `a\`,
		"utf8":      "\u043f\u0430\u0440\u043e\u043b\u044c",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "app.env")
			mustWriteFile(t, path, []byte("A=1\n"), 0o600)
			uids, gids := noAgents()
			key := testFPKey(t)
			fp, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue(v), uids, gids, key)
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			want, err := fingerprint.Compute(key, newValue(v))
			if err != nil {
				t.Fatal(err)
			}
			if fp != want {
				t.Fatalf("fingerprint of what was read back %q != fingerprint of the value %q", fp, want)
			}
			if got := mustReadFile(t, path); !strings.HasPrefix(string(got), "A=1\nX=") {
				t.Fatalf("neighbouring line lost: %s", show(got))
			}
		})
	}
}

// shellUnquote reads only what shellQuote writes.
func TestShellUnquoteRefusesOtherForms(t *testing.T) {
	for name, raw := range map[string]string{
		"unterminated": `'abc`,
		"double-quote": `"abc"`,
		"expansion":    `$HOME`,
		"space":        `a b`,
		"escape":       `a\nb`,
	} {
		if _, err := shellUnquote([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// --- JSON targets -----------------------------------------------------------

// Only a string (or nothing, or null) is a secret slot; a number, boolean,
// array or object at the field is configuration that must not be replaced.
func TestJSONPathNonStringLeafNotReplaced(t *testing.T) {
	for name, leaf := range map[string]string{"object": `{"K":"v"}`, "array": `["a"]`, "number": `7`, "bool": `true`} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "mcp.json")
			orig := `{"s":{"env":` + leaf + `}}`
			mustWriteFile(t, path, []byte(orig), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetMCPConfig, path, "s.env"), newValue("v"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrWrite, "existing "+name+" at the field")
			if got := mustReadFile(t, path); string(got) != orig {
				t.Fatalf("file changed despite the refusal: %s", show(got))
			}
		})
	}
}

// The positive control for the test above: a string and a null are replaced.
func TestJSONPathStringOrNullLeafReplaced(t *testing.T) {
	for name, leaf := range map[string]string{"string": `"old"`, "null": `null`} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "mcp.json")
			mustWriteFile(t, path, []byte(`{"s":{"env":{"K":`+leaf+`}}}`), 0o600)
			uids, gids := noAgents()
			if _, err := Write(target(runnerproto.TargetMCPConfig, path, "s.env.K"), newValue("new"), uids, gids, testFPKey(t)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := string(mustReadFile(t, path)); !strings.Contains(got, `"K": "new"`) {
				t.Fatalf("value not replaced: %s", show([]byte(got)))
			}
		})
	}
}

// --- launchd-env ------------------------------------------------------------

// The dict is found by its place in the document, not by a text search: a
// CDATA section, a string or a comment that carries a copy of the key ahead of
// the real one is not the key.
func TestLaunchdEnvDecoysAheadOfTheRealKeyIgnored(t *testing.T) {
	real := "<key>EnvironmentVariables</key>\n<dict><key>A</key><string>1</string></dict>"
	for name, decoy := range map[string]string{
		"cdata":   `<string><![CDATA[<key>EnvironmentVariables</key><dict></dict>]]></string>`,
		"escaped": `<string>&lt;key&gt;EnvironmentVariables&lt;/key&gt;&lt;dict&gt;&lt;/dict&gt;</string>`,
		"comment": `<!-- <key>EnvironmentVariables</key><dict></dict> -->`,
	} {
		t.Run(name, func(t *testing.T) {
			plist := "<plist><dict><key>ProgramArguments</key><array><string>/bin/true</string>" + decoy + "</array>\n" + real + "</dict></plist>"
			path := filepath.Join(realDir(t), "x.plist")
			mustWriteFile(t, path, []byte(plist), 0o600)
			uids, gids := noAgents()
			if _, err := Write(target(runnerproto.TargetLaunchdEnv, path, "NAME"), newValue("the-value"), uids, gids, testFPKey(t)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			want := strings.Replace(plist, "<key>A</key><string>1</string></dict></dict>", "<key>A</key><string>1</string><key>NAME</key><string>the-value</string></dict></dict>", 1)
			if got := string(mustReadFile(t, path)); got != want {
				t.Fatalf("value went to the wrong place: %s", show([]byte(got)))
			}
		})
	}
}

// A key written with a character reference is the same key for the plist
// reader: the existing entry is replaced, not shadowed by a second one.
func TestLaunchdEnvEntityEncodedKeyIsTheSameKey(t *testing.T) {
	plist := "<plist><dict><key>EnvironmentVariables</key><dict><key>NA&#77;E</key><string>old</string></dict></dict></plist>"
	path := filepath.Join(realDir(t), "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetLaunchdEnv, path, "NAME"), newValue("new"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := "<plist><dict><key>EnvironmentVariables</key><dict><key>NA&#77;E</key><string>new</string></dict></dict></plist>"
	if got := string(mustReadFile(t, path)); got != want {
		t.Fatalf("existing entry not replaced: %s", show([]byte(got)))
	}
}

// Two EnvironmentVariables keys: launchd would use one, the writer cannot know
// which.
func TestLaunchdEnvDuplicateTopLevelKeyRefused(t *testing.T) {
	plist := "<plist><dict><key>EnvironmentVariables</key><dict><key>A</key><string>1</string></dict>" +
		"<key>EnvironmentVariables</key><dict><key>B</key><string>2</string></dict></dict></plist>"
	path := filepath.Join(realDir(t), "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "NAME"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "two EnvironmentVariables keys")
	if got := string(mustReadFile(t, path)); got != plist {
		t.Fatalf("plist changed despite the refusal: %s", show([]byte(got)))
	}
}

// --- walk and temporary file ------------------------------------------------

// Every directory on the path is checked for writability, not only the last
// one: a writable directory higher up lets its writer replace a component that
// the walk has not opened yet.
func TestWritableAncestorDirRefused(t *testing.T) {
	for name, c := range map[string]struct {
		mode os.FileMode
		gids []int64
	}{
		"world-writable":       {0o777, nil},
		"agent-group-writable": {0o770, []int64{selfGID()}},
	} {
		t.Run(name, func(t *testing.T) {
			anc := filepath.Join(realDir(t), "anc")
			child := filepath.Join(anc, "child")
			if err := os.MkdirAll(child, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(anc, c.mode); err != nil { //nolint:gosec // G302: the writable directory is the scenario
				t.Fatal(err)
			}
			_, err := Write(target(runnerproto.TargetFile, filepath.Join(child, "target"), ""), newValue("v"), nil, c.gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "writable directory above the parent")
		})
	}
}

// The immediate parent is refused for either group bit alone: read (list) or
// execute (traverse).
func TestAgentReachableParentDirRefusedForEachBit(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"traverse-only": 0o710, "read-only": 0o740} {
		t.Run(name, func(t *testing.T) {
			sub := filepath.Join(realDir(t), "sub")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(sub, mode); err != nil { //nolint:gosec // G302: the reachable directory is the scenario
				t.Fatal(err)
			}
			_, gids := selfAsAgent()
			_, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), nil, gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "parent directory reachable by an agent group through one bit")
		})
	}
}

// A target mode with any one "other" bit, or any one group bit while the group
// is an agent's, is refused.
func TestTargetModeBitsEachRefused(t *testing.T) {
	for name, c := range map[string]struct {
		mode uint32
		gids []int64
	}{
		"other-x": {0o601, nil}, "other-w": {0o602, nil}, "other-r": {0o604, nil},
		"group-x": {0o610, []int64{syntheticAgentGID}}, "group-w": {0o620, []int64{syntheticAgentGID}}, "group-r": {0o640, []int64{syntheticAgentGID}},
	} {
		t.Run(name, func(t *testing.T) {
			tg := target(runnerproto.TargetFile, filepath.Join(safeDir(t), "target"), "")
			tg.Mode, tg.GID = c.mode, syntheticAgentGID
			_, err := Write(tg, newValue("v"), nil, c.gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "target mode bit")
		})
	}
}

// The walk descends by descriptor: an ancestor that has already been opened
// and is then moved away and replaced with a symlink must not redirect the
// rest of the walk. The value lands in the directory that was walked, and
// nothing reaches the attacker's.
func TestAncestorSwappedDuringWalkStaysInWalkedTree(t *testing.T) {
	dir := realDir(t)
	for _, d := range []string{filepath.Join(dir, "a", "b"), filepath.Join(dir, "evil", "b")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	orig := beforeDirOpen
	t.Cleanup(func() { beforeDirOpen = orig })
	swapped := false
	beforeDirOpen = func(_ int, seg string) {
		if seg == "b" && !swapped {
			swapped = true
			if err := os.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "a.moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "evil"), filepath.Join(dir, "a")); err != nil {
				t.Fatal(err)
			}
		}
	}
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "a", "b", "target"), ""), newValue("the-value"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !swapped {
		t.Fatal("test hook never fired")
	}
	if got := string(mustReadFile(t, filepath.Join(dir, "a.moved", "b", "target"))); got != "the-value" {
		t.Fatalf("value did not land in the walked directory: %s", show([]byte(got)))
	}
	entries, err := os.ReadDir(filepath.Join(dir, "evil", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the attacker's directory received %d entries", len(entries))
	}
}

// O_EXCL: a file planted at the temporary name is refused, not adopted. With
// the name made predictable (as it would have to be for a plant to matter),
// the write must fail and the planted file stay as it was.
func TestPlantedTemporaryNameIsNotAdopted(t *testing.T) {
	dir := realDir(t)
	orig := randomTmpName
	t.Cleanup(func() { randomTmpName = orig })
	randomTmpName = func(base string) (string, error) { return "." + base + ".tmp-fixed", nil }
	planted := filepath.Join(dir, ".target.tmp-fixed")
	mustWriteFile(t, planted, []byte("PLANTED-CONTENT"), 0o600)

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	if err == nil {
		t.Fatal("Write adopted a file planted at the temporary name")
	}
	if got := string(mustReadFile(t, planted)); got != "PLANTED-CONTENT" {
		t.Fatalf("the planted file was written through: %s", show([]byte(got)))
	}
	if _, err := os.Stat(filepath.Join(dir, "target")); err == nil {
		t.Fatal("target exists although the write was refused")
	}
}

// The mode of the temporary file is read back after Fchmod and before the
// content is written: a mode changed in that window is refused.
func TestTemporaryFileModeChangedAfterChmodRefused(t *testing.T) {
	dir := realDir(t)
	orig := afterChmod
	t.Cleanup(func() { afterChmod = orig })
	afterChmod = func(parentFD int, name string) {
		if err := unix.Fchmodat(parentFD, name, 0o644, 0); err != nil {
			t.Fatalf("inject mode change: %v", err)
		}
	}
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "temporary file mode changed before the write")
	if _, err := os.Stat(filepath.Join(dir, "target")); err == nil {
		t.Fatal("target was written despite the changed mode")
	}
}

// The group of the temporary file is read back after Fchown and before the
// content is written, the same way the owner and mode are: a group changed
// in that window is refused, not just a changed owner or mode. Needs a
// supplementary group different from the target's own to observe a change
// (as root, any group is reachable).
func TestTemporaryFileGroupChangedAfterChownRefused(t *testing.T) {
	altGID := selfGID()
	if unix.Geteuid() == 0 {
		altGID = 4243
	} else {
		groups, err := unix.Getgroups()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, g := range groups {
			if int64(g) != selfGID() && !isEveryoneGID(int64(g)) {
				altGID, found = int64(g), true
				break
			}
		}
		if !found {
			t.Skip("this test needs a supplementary group different from the primary one (or root) to observe chown")
		}
	}
	dir := realDir(t)
	orig := afterChmod
	t.Cleanup(func() { afterChmod = orig })
	afterChmod = func(parentFD int, name string) {
		if err := unix.Fchownat(parentFD, name, -1, int(altGID), 0); err != nil {
			t.Fatalf("inject group change: %v", err)
		}
	}
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "temporary file group changed before the write")
	if _, err := os.Stat(filepath.Join(dir, "target")); err == nil {
		t.Fatal("target was written despite the changed group")
	}
}

// A link added to the temporary file while the content was written is caught
// before the rename: the old target stays, and the temporary file goes.
func TestHardlinkAddedDuringWriteRefusedBeforeRename(t *testing.T) {
	dir := realDir(t)
	targetPath := filepath.Join(dir, "target")
	mustWriteFile(t, targetPath, []byte("OLD"), 0o600)
	orig := beforeRename
	t.Cleanup(func() { beforeRename = orig })
	fired := false
	beforeRename = func(parentFD int, name string) {
		fired = true
		if err := unix.Linkat(parentFD, name, unix.AT_FDCWD, filepath.Join(dir, "agent-link"), 0); err != nil {
			t.Fatalf("inject hardlink: %v", err)
		}
	}
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("NEW"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "hardlink added before the rename")
	if !fired {
		t.Fatal("test hook never fired")
	}
	if got := string(mustReadFile(t, targetPath)); got != "OLD" {
		t.Fatalf("target replaced despite the refusal: %s", show([]byte(got)))
	}
}

// The target is read back after the rename with the same checks as the
// existing target: a file swapped in at the name in between — here a hardlink
// to another service's env-file that has the field — is refused, never read
// and fingerprinted as if it were ours.
func TestReadBackRefusesTargetReplacedAfterRename(t *testing.T) {
	dir := realDir(t)
	foreign := filepath.Join(dir, "foreign.env")
	mustWriteFile(t, foreign, []byte("NAME=other\n"), 0o600)
	targetPath := filepath.Join(dir, "svc.env")
	orig := afterRename
	t.Cleanup(func() { afterRename = orig })
	fired := false
	afterRename = func(_ int, base string) {
		fired = true
		if err := os.Remove(filepath.Join(dir, base)); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(foreign, filepath.Join(dir, base)); err != nil {
			t.Fatal(err)
		}
	}
	uids, gids := noAgents()
	fp, err := Write(target(runnerproto.TargetEnvFile, targetPath, "NAME"), newValue("mine"), uids, gids, testFPKey(t))
	if err == nil {
		t.Fatalf("read back a target replaced after the rename and attested to it (%s)", fp)
	}
	if !fired {
		t.Fatal("test hook never fired")
	}
}
