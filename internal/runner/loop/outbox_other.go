//go:build !unix

package loop

import "os"

const noFollow = 0

// Off unix there is no ownership check; the runner is unix-only in practice.
func ownedByUs(os.FileInfo) bool { return true }

func syncDir(string) error { return nil }
