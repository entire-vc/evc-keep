//go:build !unix

package main

import "os"

// openPolicyFile is the non-unix fallback; FIFOs are not a concern there and
// readPolicyFile still enforces regular-file and size checks on the handle.
func openPolicyFile(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G304: operator-supplied path, same trust level as any CLI config flag
}
