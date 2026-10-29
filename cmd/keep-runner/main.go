// Command keep-runner is the on-host executor: it resolves a secret
// value from a provider and lays it down at an approved target
// (env file, systemd credential, ...). It runs as its own OS user and
// exposes no way to read a value back out — see CONTRIBUTING.md.
//
// Status: pre-alpha. `enroll`, `check` and `run` are implemented.
package main

import (
	"fmt"
	"os"

	"github.com/entire-vc/evc-keep/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:])
	case "enroll":
		return runEnroll(args[1:])
	case "run":
		return runRun(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "keep-runner %s: unknown command\n", version.String())
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "keep-runner %s\n\nCommands:\n  enroll   register this host with Keep Server\n  check    verify local credential and policy before operation\n  run      poll the server and execute signed deploy jobs\n", version.String())
}
