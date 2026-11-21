// Command leakscan looks for secret values in text. The values come from the
// files of one directory (one value per file, never printed); the text comes
// from the files named on the command line, or from stdin for "-". Each value
// is searched in the six encodings of internal/testutil/canary.
//
//	leakscan -needles DIR [-control] label=path ... label=-
//
// With -control a sample carrying each value is scanned first and must be
// caught: a scanner that is blind to its own needles fails before it reports
// anything clean. Output is one line per target: "clean <label>" or
// "LEAK <label> <needle file name>"; the exit status is 1 on any leak and 2
// when the scanner itself is broken, has no needle, or is given an empty or
// short one.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

type needle struct {
	name string
	c    canary.Canary
	raw  string
}

// sees reports whether the scanner finds the needle in the text. A variable so
// a test can make the scanner blind and prove that -control then stops it.
var sees = func(n needle, text string) bool { return n.c.In(text) }

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("leakscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("needles", "", "directory of value files")
	control := fs.Bool("control", false, "prove first that every needle is caught in a sample")
	if err := fs.Parse(args); err != nil || *dir == "" || fs.NArg() == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: leakscan -needles DIR [-control] label=path|label=- ...")
		return 2
	}
	needles, err := load(*dir)
	if err != nil || len(needles) == 0 {
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "leakscan:", err)
		} else {
			_, _ = fmt.Fprintln(stderr, "leakscan: no needles to scan for")
		}
		return 2
	}
	if *control {
		for _, n := range needles {
			for _, sample := range []string{"x" + n.raw + "y", base64.StdEncoding.EncodeToString([]byte("a" + n.raw)), url.QueryEscape(n.raw)} {
				if !sees(n, sample) {
					_, _ = fmt.Fprintf(stderr, "leakscan: blind to needle %s (positive control failed)\n", n.name)
					return 2
				}
			}
		}
		_, _ = fmt.Fprintf(stdout, "control ok %d needles\n", len(needles))
	}
	leaked := false
	for _, spec := range fs.Args() {
		label, path, ok := strings.Cut(spec, "=")
		if !ok {
			return 2
		}
		var b []byte
		if path == "-" {
			b, err = io.ReadAll(stdin)
		} else {
			b, err = os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: operator-named stand output
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "leakscan: cannot read %s\n", label)
			return 2
		}
		text, hit := string(b), ""
		for _, n := range needles {
			if sees(n, text) {
				hit = n.name
				break
			}
		}
		if hit != "" {
			leaked = true
			_, _ = fmt.Fprintf(stdout, "LEAK %s %s\n", label, hit)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "clean %s\n", label)
	}
	if leaked {
		return 1
	}
	return 0
}

func load(dir string) ([]needle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []needle
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: operator's needle directory
		if err != nil {
			return nil, err
		}
		v := strings.TrimSpace(string(b))
		if len(v) < 16 {
			// An empty or short needle cannot be searched safely, and skipping it
			// would let the scan call a text clean while not looking for it.
			return nil, fmt.Errorf("needle %s is empty or shorter than 16 bytes", e.Name())
		}
		out = append(out, needle{name: e.Name(), c: canary.Of(v), raw: v})
	}
	return out, nil
}
