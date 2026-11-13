package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// parseFlagsSafe parses args without ever echoing them. The standard parser
// quotes an unknown flag or a bad value and prints defaults, which here
// include KEEP_SERVER and KEEP_SERVER_CA: a secret pasted into the wrong
// place would land in the terminal. It prints a fixed message instead; help
// lists option names and purposes only, never defaults. ok=false means the
// caller returns rc. Positional arguments are rejected: these commands take
// none (the enrollment token arrives on stdin).
func parseFlagsSafe(fs *flag.FlagSet, cmd string, args []string) (rc int, ok bool) {
	fs.SetOutput(discard{})
	// Probe the separator first: the probe re-parses prefixes and would
	// otherwise reset fs.Args(), hiding a positional tail from NArg below.
	bare := hasBareSeparator(fs, args)
	err := fs.Parse(args)
	if err == nil && bare {
		err = errBareSeparator
	}
	switch {
	case errors.Is(err, flag.ErrHelp):
		printFlagHelp(fs, cmd)
		return 0, false
	case err != nil, fs.NArg() != 0:
		fmt.Fprintf(os.Stderr, "keep-runner %s: invalid arguments (see keep-runner %s -h)\n", cmd, cmd)
		return 2, false
	}
	return 0, true
}

var errBareSeparator = errors.New("bare separator")

// hasBareSeparator reports whether a "--" in args ends the flag list, as
// opposed to being the value of a preceding flag (-host --). flag.Parse eats
// the separator, so a trailing one would otherwise pass unnoticed. A prefix
// that parses cleanly up to a "--" means that "--" was the terminator.
func hasBareSeparator(fs *flag.FlagSet, args []string) bool {
	for i, a := range args {
		if a == "--" && fs.Parse(args[:i]) == nil {
			return true
		}
	}
	return false
}

func printFlagHelp(fs *flag.FlagSet, cmd string) {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: keep-runner %s [options]\n\nOptions:\n", cmd)
	fs.VisitAll(func(f *flag.Flag) {
		fmt.Fprintf(&b, "  -%s\n    \t%s\n", f.Name, f.Usage)
	})
	fmt.Fprint(os.Stderr, b.String())
}
