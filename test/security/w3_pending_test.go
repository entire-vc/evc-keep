package security

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Match target names under internal/ and pkg/, including alternate paths.
var w3PackageDirs = map[string]*regexp.Regexp{
	"carriers":    regexp.MustCompile(`(?i)carrier`),
	"scanner":     regexp.MustCompile(`(?i)scan|sprawl`),
	"rotationapi": regexp.MustCompile(`(?i)rotationapi|rotation_api|rotationhttp`),
}

// w3Pending marks an attack stub as waiting for its package. The skip is
// legal only while its own target is absent. A different target does not
// activate it. check-w3-stubs.sh plants each missing target independently.
func w3Pending(t *testing.T, id, target string) {
	t.Helper()
	pattern, ok := w3PackageDirs[target]
	if !ok {
		t.Fatal("unknown pending target")
	}
	root := w3Root(t)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal("cannot inspect pending target root")
	}
	dir, err := w3FindPackage(root, pattern)
	if err != nil {
		t.Fatal("cannot inspect pending target package")
	}
	if dir != "" {
		t.Fatalf("%s: pending target %s exists; implement this attack", id, target)
	}
	t.Skip(id + ": pending target " + target + " absent")
}

func w3Root(t *testing.T) string {
	t.Helper()
	if r := os.Getenv("KEEP_W3_ROOT"); r != "" { // set by the red-control script
		return r
	}
	// go test runs with the package directory (test/security) as cwd; the
	// build flags here include -trimpath, so runtime.Caller is no use.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal("cannot locate repo root:", err)
	}
	return filepath.Join(wd, "..", "..")
}

func w3FindPackage(root string, pattern *regexp.Regexp) (string, error) {
	for _, top := range []string{"internal", "pkg"} {
		var found string
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// WalkDir does not follow symbolic links. An unresolved entry
			// cannot establish that a target is absent.
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("symbolic link in pending package inventory")
			}
			if found != "" || !d.IsDir() || !pattern.MatchString(d.Name()) {
				return nil
			}
			ents, err := os.ReadDir(p)
			if err != nil {
				return err
			}
			for _, e := range ents {
				n := e.Name()
				if strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
					found = p
					return filepath.SkipAll
				}
			}
			return nil
		})
		if err != nil || found != "" {
			return found, err
		}
	}
	return "", nil
}
