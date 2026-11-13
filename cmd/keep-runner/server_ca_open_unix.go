//go:build unix

package main

import (
	"os"
	"syscall"
)

func openNonBlocking(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) //nolint:gosec // G304: operator-supplied path, same trust level as any CLI config flag
}
