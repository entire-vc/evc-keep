//go:build unix

package targets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"golang.org/x/sys/unix"
)

// Guards that the independent red-run review found green with the protection
// switched off, or red only because the mutant crashed the test binary.

// callRecovering runs f and reports whether it panicked.
func callRecovering(f func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	f()
	return false
}

// The scanners index into lines they did not build. Every short combination of
// the tokens that steer them (export, names, quotes, backslash, blanks, comment,
// newline) goes through every entry point of both dialects: a removed bounds
// check is a failed assertion here, not a crashed test binary.
func TestEnvScanNeverPanics(t *testing.T) {
	tokens := []string{"export", "NAME", "A_LONG_NAME", "=", "'", `"`, `\`, " ", "\t", "#", "\n", "x", "\r", "$"}
	tg := target(runnerproto.TargetEnvFile, "/unused", "NAME")
	panics, first := 0, ""
	try := func(what, in string, f func()) {
		if callRecovering(f) {
			if panics == 0 {
				first = what + " on " + strings.ReplaceAll(in, "\n", `\n`)
			}
			panics++
		}
	}
	var walk func(prefix string, depth int)
	walk = func(prefix string, depth int) {
		in := []byte(prefix)
		for _, d := range []envDialect{dialectShell, dialectDotenv} {
			try("lineIsSimple", prefix, func() { lineIsSimple(in, d) })
			try("existingIsSimple", prefix, func() { existingIsSimple(in, d) })
			try("assignsField", prefix, func() { assignsField(in, "NAME", d) })
			try("envReadBack", prefix, func() { _, _ = envReadBack(d, in, tg) })
			try("envBuild", prefix, func() { _, _ = envBuild(d, in, true, tg, newValue("v")) })
		}
		try("shellUnquote", prefix, func() { _, _ = shellUnquote(in) })
		try("countAssignmentNames", prefix, func() { countAssignmentNames(in) })
		try("hermesMisreads", prefix, func() { hermesMisreads(in) })
		if depth == 0 {
			return
		}
		for _, tok := range tokens {
			walk(prefix+tok, depth-1)
		}
	}
	walk("", 4)
	if panics > 0 {
		t.Fatalf("%d panics in the env scanners, the first: %s", panics, first)
	}
}

// A syntax error inside the EnvironmentVariables dict is refused: the token
// loop must stop at it, not spin on the same offset.
func TestLaunchdSyntaxErrorInDictRefused(t *testing.T) {
	plist := `<plist><dict><key>EnvironmentVariables</key><dict><key>A</key><string>&bogus;</string></dict></dict></plist>`
	path := filepath.Join(realDir(t), "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	done := make(chan error, 1)
	go func() {
		_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
		done <- err
	}()
	select {
	case err := <-done:
		wantErr(t, err, ErrWrite, "syntax error inside EnvironmentVariables")
	case <-time.After(10 * time.Second):
		t.Fatal("Write did not return on a syntax error inside the dict")
	}
	if got := string(mustReadFile(t, path)); got != plist {
		t.Fatalf("plist changed despite the refusal: %s", show([]byte(got)))
	}
}

// Scalar neighbours other than a string are ordinary entries of the dict.
func TestLaunchdScalarNeighboursKeptByteForByte(t *testing.T) {
	plist := `<plist><dict><key>EnvironmentVariables</key><dict>` +
		`<key>I</key><integer>7</integer><key>R</key><real>1.5</real><key>T</key><true/><key>F</key><false/>` +
		`<key>D</key><data>QUJD</data><key>W</key><date>2026-01-01T00:00:00Z</date>` +
		`</dict></dict></plist>`
	path := filepath.Join(realDir(t), "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write refused a dict with non-string scalar neighbours: %v", err)
	}
	got := string(mustReadFile(t, path))
	for _, n := range []string{"<integer>7</integer>", "<real>1.5</real>", "<true/>", "<false/>", "<data>QUJD</data>", "<date>2026-01-01T00:00:00Z</date>"} {
		if !strings.Contains(got, n) {
			t.Errorf("neighbour %s lost", n)
		}
	}
}

// The read back that produces the fingerprint must find the field it wrote: a
// file without it is an error, not an empty value with a valid fingerprint.
func TestEnvReadBackRefusesAFileWithoutTheField(t *testing.T) {
	tg := target(runnerproto.TargetEnvFile, "/unused", "NAME")
	for _, d := range []envDialect{dialectShell, dialectDotenv} {
		for _, content := range []string{"", "OTHER=1\n", "# NAME=1\n"} {
			if _, err := envReadBack(d, []byte(content), tg); err == nil {
				t.Errorf("dialect %d: a file without NAME was read back (%d bytes)", d, len(content))
			}
		}
	}
}

// A fingerprint that cannot be computed fails the write: an empty fingerprint
// with a nil error would be reported to the server as success.
func TestWriteFailsWhenTheFingerprintCannotBeComputed(t *testing.T) {
	path := filepath.Join(safeDir(t), "target")
	uids, gids := noAgents()
	fp, err := Write(target(runnerproto.TargetFile, path, ""), newValue("v"), uids, gids, fingerprint.Key{})
	if err == nil {
		t.Fatalf("Write with an unusable fingerprint key succeeded, fingerprint %q", fp)
	}
	if fp != "" {
		t.Errorf("a failed Write returned a fingerprint: %q", fp)
	}
	// Refused before the write: the value must not be on disk.
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("the target exists although the fingerprint key was unusable")
	}
}

// End tags that do not close the element they follow are refused: RawToken does
// not check them, and a dict whose structure is not what it looks like is not
// one to write into.
func TestLaunchdMismatchedEndTagInDictRefused(t *testing.T) {
	for name, plist := range map[string]string{
		"string closed as key": `<plist><dict><key>EnvironmentVariables</key><dict><key>A</key><string>x</key></dict></dict></plist>`,
		"key closed as string": `<plist><dict><key>EnvironmentVariables</key><dict><key>A</string><string>x</string></dict></dict></plist>`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "x.plist")
			mustWriteFile(t, path, []byte(plist), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrWrite, "mismatched end tag")
			if got := string(mustReadFile(t, path)); got != plist {
				t.Fatalf("plist changed despite the refusal: %s", show([]byte(got)))
			}
		})
	}
}

// Lines that begin like an export but are not one, and lines that merely look
// like an assignment of a name, are ordinary neighbours.
func TestEnvNeighboursThatLookLikeOtherEntries(t *testing.T) {
	// A bare "export" line is a command to a shell (it lists the variables), so
	// only the dotenv reader takes it as an ordinary line.
	cases := []struct {
		name, existing, want string
		kinds                []runnerproto.TargetKind
	}{
		{"a bare export line after the field", "NAME=old\nexport\n", "NAME=v\nexport\n", []runnerproto.TargetKind{runnerproto.TargetHermesConfig}},
		{"exportNAME is another name", "NAME=old\nexportNAME=1\n", "NAME=v\nexportNAME=1\n", []runnerproto.TargetKind{runnerproto.TargetEnvFile, runnerproto.TargetHermesConfig}},
	}
	for _, c := range cases {
		for _, kind := range c.kinds {
			t.Run(string(kind)+"/"+c.name, func(t *testing.T) {
				path := filepath.Join(realDir(t), "svc.env")
				mustWriteFile(t, path, []byte(c.existing), 0o600)
				uids, gids := noAgents()
				if _, err := Write(target(kind, path, "NAME"), newValue("v"), uids, gids, testFPKey(t)); err != nil {
					t.Fatalf("Write: %v", err)
				}
				if got := string(mustReadFile(t, path)); got != c.want {
					t.Fatalf("got %s, want %s", show([]byte(got)), show([]byte(c.want)))
				}
			})
		}
	}
}

// Hermes cuts a line at every known variable name followed by an equals sign;
// runs of capitals broken by another character, and a doubled equals sign, are
// not that. A backslash with no quote in the line is plain text for dotenv.
func TestHermesNeighboursThatOnlyLookRisky(t *testing.T) {
	for _, existing := range []string{
		"P=c:\\dir\n",
		"A_LONG_NAMEx=1 B_LONG_NAMEy=2\n",
		"ABCDEFG==1\n",
	} {
		path := filepath.Join(realDir(t), ".env")
		mustWriteFile(t, path, []byte(existing), 0o600)
		uids, gids := noAgents()
		if _, err := Write(target(runnerproto.TargetHermesConfig, path, "NAME"), newValue("v"), uids, gids, testFPKey(t)); err != nil {
			t.Errorf("neighbour of %d bytes refused: %v", len(existing), err)
			continue
		}
		if got := mustReadFile(t, path); !bytes.HasPrefix(got, []byte(existing)) {
			t.Errorf("neighbour of %d bytes was not kept as it was", len(existing))
		}
	}
}

// Read and traverse by an agent group matter on the directory that holds the
// target, and only there; the owner bits of that directory are not the
// group's, and a group-readable directory further up the path is not refused.
func TestAgentReachRuleIsTheGroupBitsOfTheParentOnly(t *testing.T) {
	_, gids := selfAsAgent()
	t.Run("owner bits alone", func(t *testing.T) {
		dir := safeDir(t) // 0700: the owner reads it, the group does not
		if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), nil, gids, testFPKey(t)); err != nil {
			t.Fatalf("a 0700 parent was refused for the agent group: %v", err)
		}
	})
	t.Run("ancestor readable by the agent group", func(t *testing.T) {
		up := filepath.Join(realDir(t), "up")
		if err := os.Mkdir(up, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(up, 0o750); err != nil { //nolint:gosec // G302: the group-readable ancestor is what this test lets through
			t.Fatal(err)
		}
		inner := filepath.Join(up, "inner")
		if err := os.Mkdir(inner, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(target(runnerproto.TargetFile, filepath.Join(inner, "target"), ""), newValue("v"), nil, gids, testFPKey(t)); err != nil {
			t.Fatalf("a group-readable ancestor above a 0700 parent was refused: %v", err)
		}
	})
}

// A JSON document whose top level is null decodes to a nil map; writing into it
// is a refusal, not a crash of the runner.
func TestJSONTopLevelNullRefused(t *testing.T) {
	path := filepath.Join(realDir(t), "mcp.json")
	mustWriteFile(t, path, []byte("null"), 0o600)
	uids, gids := noAgents()
	var err error
	if callRecovering(func() {
		_, err = Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.x.env.K"), newValue("v"), uids, gids, testFPKey(t))
	}) {
		t.Fatal("Write panicked on a JSON file whose top level is null")
	}
	wantErr(t, err, ErrWrite, "top-level null")
	if got := string(mustReadFile(t, path)); got != "null" {
		t.Fatalf("file changed despite the refusal: %s", show([]byte(got)))
	}
}

// The descriptor opened on an existing target is close-on-exec too: a child the
// runner starts later must not inherit an open handle on another service's file.
func TestExistingFDIsCloexec(t *testing.T) {
	path := filepath.Join(realDir(t), "x")
	mustWriteFile(t, path, []byte("old"), 0o600)
	var flags []int
	old := afterExistingOpen
	afterExistingOpen = func(fd int) {
		fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			fl = -1
		}
		flags = append(flags, fl)
	}
	defer func() { afterExistingOpen = old }()
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, path, ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatal(err)
	}
	if len(flags) < 2 {
		t.Fatalf("the hook fired %d times; the check would be vacuous", len(flags))
	}
	for _, fl := range flags {
		if fl < 0 || fl&unix.FD_CLOEXEC == 0 {
			t.Fatalf("a descriptor opened on the existing target is not close-on-exec (flags %d)", fl)
		}
	}
}

// An end tag with nothing open is malformed, not an index out of range.
func TestLaunchdStrayEndTagRefused(t *testing.T) {
	for name, plist := range map[string]string{
		"leading":  `</x><plist><dict><key>EnvironmentVariables</key><dict></dict></dict></plist>`,
		"trailing": `<plist><dict><key>EnvironmentVariables</key><dict></dict></dict></plist></x>`,
		"only":     `</x>`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "x.plist")
			mustWriteFile(t, path, []byte(plist), 0o600)
			uids, gids := noAgents()
			var err error
			if callRecovering(func() {
				_, err = Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
			}) {
				t.Fatal("Write panicked on a stray end tag")
			}
			wantErr(t, err, ErrWrite, "stray end tag")
			if got := string(mustReadFile(t, path)); got != plist {
				t.Fatalf("plist changed despite the refusal: %s", show([]byte(got)))
			}
		})
	}
}

// show() is what every failure message uses in place of file content: the same
// bytes give the same digest, different bytes a different one, and a broken key
// does not degrade it to a constant.
func TestShowDigestDistinguishesContents(t *testing.T) {
	a, b := []byte("first"), []byte("second")
	if again := append([]byte(nil), a...); show(a) != show(again) {
		t.Errorf("the same bytes give two digests: %s vs %s", show(a), show(again))
	}
	if show(a) == show(b) {
		t.Errorf("different bytes give the same description: %s", show(a))
	}
	if strings.Contains(show(a), "digest ?") {
		t.Errorf("the digest key is unusable: %s", show(a))
	}
}
