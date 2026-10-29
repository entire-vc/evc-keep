package main

import (
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policy == "" {
		fmt.Fprintln(os.Stderr, "keep-runner check: -policy is required")
		return 2
	}
	cred, err := runner.Load(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner check: %v\n", err)
		return 1
	}
	defer clear(cred.Key)
	pol, err := runnerproto.LoadHostPolicy(*policy, os.Getuid())
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep-runner check: invalid local policy or insecure policy file")
		return 1
	}
	// A prefix through a symlink would be admitted and then denied on every
	// write. The error names a configured path, never a value.
	if err := runnerproto.CheckPrefixesOnHost(pol); err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner check: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(os.Stdout, "credential and local policy verified")
	return 0
}
