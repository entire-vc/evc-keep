//go:build unix

package targets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/carriers/meshkey"
)

// noEcho fails if msg repeats any part of the carrier locator the caller
// supplied: its path, directory, file name or field.
func noEcho(t *testing.T, msg string, c meshkey.Carrier) {
	t.Helper()
	for _, echo := range []string{c.Path, filepath.Dir(c.Path), filepath.Base(c.Path), c.Field} {
		if len(echo) > 3 && strings.Contains(msg, echo) {
			t.Fatalf("error echoes the locator %q: %q", echo, msg)
		}
	}
}

// TestVerifyCarrierOutsideRootsOpensNothing: a carrier of the manifest whose
// file is not under a configured root is refused before any open, whatever
// the way it gets outside: its own path, a symlink to it, a symlinked directory.
func TestVerifyCarrierOutsideRootsOpensNothing(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t) // files live in f.dir
	good := f.fp(t, f.target)
	opens := countOpens(t)

	root := t.TempDir() // the configured root: holds none of the files

	link := func(t *testing.T, c meshkey.Carrier, at string) meshkey.Carrier {
		t.Helper()
		c.Path = at
		c.Metadata.TargetPath = at
		return c
	}
	// File symlink inside the root pointing at a real carrier file outside.
	inRootLink := filepath.Join(root, ".mcp.json")
	if err := os.Symlink(cs[0].Path, inRootLink); err != nil {
		t.Fatal(err)
	}
	// Directory symlink inside the root pointing at the directory outside.
	dirLink := filepath.Join(root, "lane")
	if err := os.Symlink(f.dir, dirLink); err != nil {
		t.Fatal(err)
	}
	cases := map[string]meshkey.Carrier{
		"path outside roots":         cs[0],
		"file symlink out of root":   link(t, cs[0], inRootLink),
		"directory symlink out":      link(t, cs[0], filepath.Join(dirLink, ".mcp.json")),
		"env file outside roots":     cs[3],
		"fiddler json outside roots": cs[2],
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before := *opens
			got, err := VerifyCarrier([]string{root}, 1, c, good, f.key)
			if !errors.Is(err, ErrPolicy) || got != "" {
				t.Fatalf("got %q %v, want ErrPolicy", got, err)
			}
			if *opens != before {
				t.Fatalf("a file was opened outside the roots (%d opens)", *opens-before)
			}
			noEcho(t, err.Error(), c)
			if f.seen(err.Error()) {
				t.Fatalf("secret in error: %q", err)
			}
		})
	}
}

// TestVerifyCarrierEmptyRootsRefuseEverything: no roots means no carrier is
// allowed (fail closed), and so does a root that is not a clean absolute path.
func TestVerifyCarrierEmptyRootsRefuseEverything(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t)
	good := f.fp(t, f.target)
	opens := countOpens(t)
	for name, roots := range map[string][]string{
		"nil":          nil,
		"empty":        {},
		"blank entry":  {""},
		"relative":     {"rel"},
		"dot":          {"."},
		"filesystem /": {"/"},
		"unclean":      {f.dir + "/../" + filepath.Base(f.dir)},
	} {
		for _, c := range cs {
			if got, err := VerifyCarrier(roots, 1, c, good, f.key); !errors.Is(err, ErrPolicy) || got != "" {
				t.Fatalf("%s/%s: got %q %v, want ErrPolicy", name, c.Kind, got, err)
			}
		}
	}
	if *opens != 0 {
		t.Fatalf("a file was opened with no usable root (%d opens)", *opens)
	}
}

// TestVerifyCarrierAgentEnvSitsDirectlyInARoot: an env file one level down is
// refused even though it is under the root; the same file in the root is read.
func TestVerifyCarrierAgentEnvSitsDirectlyInARoot(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t)
	good := f.fp(t, f.target)
	opens := countOpens(t)

	sub := filepath.Join(f.dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(sub, "sage.env")
	if err := os.WriteFile(deep, []byte("MESH_AGENT_KEY="+f.target+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := cs[3]
	c.Path, c.Metadata.TargetPath = deep, deep
	before := *opens
	if got, err := VerifyCarrier([]string{f.dir}, 1, c, good, f.key); !errors.Is(err, ErrPolicy) || got != "" {
		t.Fatalf("env file in a subdirectory: got %q %v, want ErrPolicy", got, err)
	}
	if *opens != before {
		t.Fatal("the nested env file was opened")
	}
	// A subdirectory root makes the same file a direct child: allowed.
	if got, err := VerifyCarrier([]string{sub}, 1, c, good, f.key); err != nil || got != VerifyMatch {
		t.Fatalf("env file directly in its root: got %q %v", got, err)
	}
	// Other kinds may sit below the root.
	nested := cs[0]
	nestedPath := filepath.Join(sub, ".mcp.json")
	mcp := `{"mcpServers":{"evc-mesh":{"env":{"MESH_AGENT_KEY":"` + f.target + `"}}}}`
	if err := os.WriteFile(nestedPath, []byte(mcp), 0o600); err != nil {
		t.Fatal(err)
	}
	nested.Path, nested.Metadata.TargetPath = nestedPath, nestedPath
	if got, err := VerifyCarrier([]string{f.dir}, 1, nested, good, f.key); err != nil || got != VerifyMatch {
		t.Fatalf("lane file below a root: got %q %v", got, err)
	}
}

// TestVerifyCarrierInRootsReadsOnceEach: positive control, one open per carrier.
func TestVerifyCarrierInRootsReadsOnceEach(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t)
	good := f.fp(t, f.target)
	opens := countOpens(t)
	for i, c := range cs {
		before := *opens
		got, err := VerifyCarrier([]string{f.dir}, i+1, c, good, f.key)
		if err != nil || got != VerifyMatch || *opens != before+1 {
			t.Fatalf("%s: got %q %v, opens %d", c.Kind, got, err, *opens-before)
		}
	}
}

// TestVerifyCarrierErrorsNameKindAndOrdinalOnly: a refusal made while reading
// names the carrier by kind and ordinal and carries no path or field, in the
// error text, whatever the failure.
func TestVerifyCarrierErrorsNameKindAndOrdinalOnly(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t)
	good := f.fp(t, f.target)
	f.write(t, ".mcp.json", "{not json")
	f.write(t, "mesh-agents.json", `{"agents":[{"name":"Sage","agent_key":"x"},{"name":"Sage","agent_key":"y"}]}`)
	f.write(t, "fiddler.json", `{"agents":"not-an-array"}`)
	f.write(t, "sage.env", "MESH_AGENT_KEY=$(cmd)\n")

	for i, c := range cs {
		_, err := VerifyCarrier([]string{f.dir}, i+7, c, good, f.key)
		if err == nil {
			t.Fatalf("%s: expected a refusal", c.Kind)
		}
		msg := err.Error()
		noEcho(t, msg, c)
		if !strings.Contains(msg, string(c.Kind)) || !strings.Contains(msg, fmt.Sprintf("#%d", i+7)) {
			t.Fatalf("%s: the error names neither kind nor ordinal: %q", c.Kind, msg)
		}
		if f.seen(msg) {
			t.Fatalf("secret in error: %q", msg)
		}
	}
	// Bad expected fingerprint and an unreadable-as-file carrier too.
	if _, err := VerifyCarrier([]string{f.dir}, 1, cs[0], "not-a-fingerprint", f.key); err == nil {
		t.Fatal("expected a refusal for a malformed fingerprint")
	} else {
		noEcho(t, err.Error(), cs[0])
	}
	dirCarrier := cs[3]
	dirPath := filepath.Join(f.dir, "dir.env")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	dirCarrier.Path, dirCarrier.Metadata.TargetPath = dirPath, dirPath
	if _, err := VerifyCarrier([]string{f.dir}, 1, dirCarrier, good, f.key); err == nil {
		t.Fatal("expected a refusal for a directory")
	} else {
		noEcho(t, err.Error(), dirCarrier)
	}
	// A manifest refusal names no kind either: the kind is caller input.
	foreign := cs[0]
	foreign.Kind = meshkey.Kind("shadow-kind")
	if _, err := VerifyCarrier([]string{f.dir}, 1, foreign, good, f.key); err == nil || strings.Contains(err.Error(), "shadow-kind") {
		t.Fatalf("manifest refusal echoes the kind: %v", err)
	}
}

// TestVerifySpecErrorsCarryNoLocator: the inner reads refuse without path or field.
func TestVerifySpecErrorsCarryNoLocator(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	bad := f.write(t, "broken-canary-name.json", "{not json")
	dir := filepath.Join(f.dir, "dir-canary-name.json")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.dir, "link-canary-name.json")
	if err := os.Symlink(bad, link); err != nil {
		t.Fatal(err)
	}
	for name, spec := range map[string]readSpec{
		"malformed":       {formatJSON, bad, "field-canary"},
		"unknown format":  {"xml-canary", bad, "field-canary"},
		"directory":       {formatJSON, dir, "field-canary"},
		"symlink":         {formatJSON, link, "field-canary"},
		"selector":        {formatJSON, bad, "a[field-canary"},
		"env var":         {formatEnv, bad, "field canary"},
		"relative":        {formatJSON, "rel-canary/x.json", "field-canary"},
		"not an object":   {formatJSON, f.write(t, "s-canary-name.json", `["x"]`), "field-canary"},
		"not a string":    {formatJSON, f.write(t, "n-canary-name.json", `{"field-canary":{}}`), "field-canary"},
		"ambiguous":       {formatJSON, f.write(t, "d-canary-name.json", `{"a":[{"k":"v"},{"k":"v"}]}`), "a[k=v].x-canary"},
		"not array":       {formatJSON, f.write(t, "r-canary-name.json", `{"a":{}}`), "a[k=v-canary].z"},
		"walk not object": {formatJSON, f.write(t, "w-canary-name.json", `{"a":"s"}`), "a.b-canary"},
	} {
		_, err := verifySpec(spec, good, f.key)
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if strings.Contains(err.Error(), "canary") {
			t.Fatalf("%s: the error echoes the locator: %q", name, err)
		}
	}
}

// TestVerifyCarrierSwapAfterCheckStaysInRoot: a directory below the root is
// swapped for a link to the outside right before the file is opened; the read
// still comes from the file the directory held when it was checked, never
// from the outside.
func TestVerifyCarrierSwapAfterCheckStaysInRoot(t *testing.T) {
	f := newVerifyFixture(t)
	root := t.TempDir()
	outside := t.TempDir()
	lane := filepath.Join(root, "lane")
	if err := os.Mkdir(lane, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(dir, key string) {
		t.Helper()
		body := `{"mcpServers":{"evc-mesh":{"env":{"MESH_AGENT_KEY":"` + key + `"}}}}`
		if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(lane, f.target)
	write(outside, f.others[0])
	cs, err := meshkey.For(meshkey.Agent{Host: "h", Name: "Sage", LaneDir: lane, BinDir: lane, CfgDir: lane, EnvDir: lane, EnvFile: "sage.env"})
	if err != nil {
		t.Fatal(err)
	}
	prev := openCarrier
	swapped := false
	openCarrier = func(dirfd int, p string, flags int, mode uint32) (int, error) {
		if !swapped {
			swapped = true
			if err := os.Rename(lane, lane+".old"); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(outside, lane); err != nil {
				t.Error(err)
			}
		}
		return prev(dirfd, p, flags, mode)
	}
	t.Cleanup(func() { openCarrier = prev })
	got, err := VerifyCarrier([]string{root}, 1, cs[0], f.fp(t, f.target), f.key)
	if err != nil || got != VerifyMatch {
		t.Fatalf("a swap after the check led the read outside the root: got %q %v", got, err)
	}
	if !swapped {
		t.Fatal("the swap never ran")
	}
}

// TestVerifyCarrierLinksBelowTheRootNeverAnswerAbsent: a link below the root
// is refused whether or not the directory behind it exists, so the answer does
// not tell whether a path outside the root exists; a root that resolves to the
// filesystem root is refused.
func TestVerifyCarrierLinksBelowTheRootNeverAnswerAbsent(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(outside, "exists"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "lnk")); err != nil {
		t.Fatal(err)
	}
	mk := func(p string) meshkey.Carrier {
		cs, err := meshkey.For(meshkey.Agent{Host: "h", Name: "Sage", LaneDir: filepath.Dir(p), BinDir: filepath.Dir(p), CfgDir: filepath.Dir(p), EnvDir: filepath.Dir(p), EnvFile: "sage.env"})
		if err != nil {
			t.Fatal(err)
		}
		return cs[0]
	}
	for _, sub := range []string{"exists", "missing"} {
		got, err := VerifyCarrier([]string{root}, 1, mk(filepath.Join(root, "lnk", sub, ".mcp.json")), good, f.key)
		if !errors.Is(err, ErrPolicy) || got != "" {
			t.Fatalf("%s behind a link: got %q %v, want ErrPolicy", sub, got, err)
		}
	}
	// A missing directory under the root itself is plain absent.
	if got, err := VerifyCarrier([]string{root}, 1, mk(filepath.Join(root, "nolane", ".mcp.json")), good, f.key); err != nil || got != VerifyAbsent {
		t.Fatalf("missing lane under the root: got %q %v", got, err)
	}
	// A root that is a link to the filesystem root.
	slash := filepath.Join(t.TempDir(), "slash")
	if err := os.Symlink("/", slash); err != nil {
		t.Fatal(err)
	}
	cs := f.agentCarriers(t)
	env := cs[3]
	env.Path = slash + "/x.env"
	env.Metadata.TargetPath = env.Path
	if got, err := VerifyCarrier([]string{slash}, 1, env, good, f.key); !errors.Is(err, ErrPolicy) || got != "" {
		t.Fatalf("a root resolving to /: got %q %v, want ErrPolicy", got, err)
	}
}

// TestVerifyCarrierSiblingWithTheSamePrefixIsOutside: root/ and root2/ share a
// name prefix; a carrier in root2 is not under root.
func TestVerifyCarrierSiblingWithTheSamePrefixIsOutside(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	base := t.TempDir()
	root, sibling := filepath.Join(base, "root"), filepath.Join(base, "root2")
	for _, d := range []string{root, sibling} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	body := `{"mcpServers":{"evc-mesh":{"env":{"MESH_AGENT_KEY":"` + f.target + `"}}}}`
	if err := os.WriteFile(filepath.Join(sibling, ".mcp.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := meshkey.For(meshkey.Agent{Host: "h", Name: "Sage", LaneDir: sibling, BinDir: sibling, CfgDir: sibling, EnvDir: sibling, EnvFile: "sage.env"})
	if err != nil {
		t.Fatal(err)
	}
	opens := countOpens(t)
	if got, err := VerifyCarrier([]string{root}, 1, cs[0], good, f.key); !errors.Is(err, ErrPolicy) || got != "" || *opens != 0 {
		t.Fatalf("sibling with a shared prefix: got %q %v, opens %d", got, err, *opens)
	}
	if got, err := VerifyCarrier([]string{sibling}, 1, cs[0], good, f.key); err != nil || got != VerifyMatch {
		t.Fatalf("positive control: got %q %v", got, err)
	}
}

// TestDescendRefusesNonCleanComponents: descend does not rely on the manifest
// alone to keep ".." out of a path.
func TestDescendRefusesNonCleanComponents(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"../x.env", "a/../x.env", "./x.env", "a//x.env", ""} {
		fd, _, absent, err := descend(root, rel)
		if !errors.Is(err, ErrPolicy) || absent || fd >= 0 {
			t.Fatalf("%q: fd %d absent %v err %v, want ErrPolicy", rel, fd, absent, err)
		}
	}
}

// A hard link inside a root to a file outside it reads as the file's own
// content; without the link-count check Verify would answer for it.
func TestVerifyCarrierHardLinkIsRefused(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t)
	good := f.fp(t, f.target)
	outside := filepath.Join(t.TempDir(), "outside.env")
	if err := os.WriteFile(outside, []byte("MESH_AGENT_KEY="+f.target+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(f.dir, "linked.env")
	if err := os.Link(outside, linked); err != nil {
		t.Skipf("hard links are not available here: %v", err)
	}
	c := cs[3]
	c.Path, c.Metadata.TargetPath = linked, linked
	got, err := VerifyCarrier([]string{f.dir}, 1, c, good, f.key)
	if !errors.Is(err, ErrPolicy) || got != "" {
		t.Fatalf("hard-linked carrier: got %q %v, want ErrPolicy", got, err)
	}
	noEcho(t, err.Error(), c)
	// Positive control: the same file with one link verifies.
	if got, err := VerifyCarrier([]string{f.dir}, 1, cs[3], good, f.key); err != nil || got != VerifyMatch {
		t.Fatalf("single-link carrier: got %q %v", got, err)
	}
}

// The env carrier verifies the agent key variable only: a neighbour variable
// in the same file is refused before any open.
func TestVerifyCarrierRefusesForeignEnvVariable(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t)
	opens := countOpens(t)
	c := cs[3]
	c.Field, c.Metadata.TargetField = "OTHER", "OTHER"
	before := *opens
	got, err := VerifyCarrier([]string{f.dir}, 1, c, f.fp(t, f.others[0]), f.key)
	if !errors.Is(err, ErrPolicy) || got != "" {
		t.Fatalf("neighbour variable: got %q %v, want ErrPolicy", got, err)
	}
	if *opens != before {
		t.Fatal("the env file was opened for a foreign variable")
	}
	noEcho(t, err.Error(), c)
}
