//go:build !unix

package main

import "os"

func openNonBlocking(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G304: operator-supplied path, same trust level as any CLI config flag
}
