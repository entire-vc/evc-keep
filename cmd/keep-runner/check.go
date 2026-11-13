package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// runCheck verifies the credential and local policy before operating this host.
// The service account owns both: deployments run this as keep or _keep.
func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	dir := fs.String("cred-dir", defaultCredDir, "directory holding the enrollment credential")
	policy := fs.String("policy", "", "path to the host policy")
	if rc, ok := parseFlagsSafe(fs, "check", args); !ok {
		return rc
	}
	if *policy == "" {
		fmt.Fprintln(os.Stderr, "keep-runner check: -policy is required")
		return 2
	}
	cred, err := runner.Load(*dir)
	if err != nil {
		// err quotes the -cred-dir path; only a static line is printed.
		fmt.Fprintln(os.Stderr, "keep-runner check: credential is missing, unreadable or insecure")
		return 1
	}
	defer clear(cred.Key)
	pol, err := runnerproto.LoadHostPolicy(*policy, os.Getuid())
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep-runner check: invalid local policy or insecure policy file")
		return 1
	}
	// A prefix through a symlink would be admitted and then denied on every
	// write. The policy file is arbitrary text, so only the class and the
	// rule/prefix indexes are printed, never its content or a resolved path.
	if err := runnerproto.CheckPrefixesOnHost(pol); err != nil {
		var pe *runnerproto.PrefixError
		if errors.As(err, &pe) {
			fmt.Fprintf(os.Stderr, "keep-runner check: policy rule %d prefix %d is refused (%s); inspect it on the host\n", pe.Rule, pe.Prefix, pe.Class)
		} else {
			fmt.Fprintln(os.Stderr, "keep-runner check: policy prefix check failed")
		}
		return 1
	}
	_, _ = fmt.Fprintln(os.Stdout, "credential and local policy verified")
	return 0
}
