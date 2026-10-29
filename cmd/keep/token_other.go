//go:build !unix

package main

import "os"

// openTokenFileNoFollow is the non-unix fallback: no portable way to refuse
// following a symlink at open time exists on this platform family, so the
// symlink gap resolveToken otherwise closes on unix is a residual gap here.
func openTokenFileNoFollow(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G304: path is the caller's own --token-file/default config path, permission-checked before any byte is read; symlink-following is this platform's documented residual gap, not an oversight
}
