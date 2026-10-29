//go:build !unix

package execrun

import "os"

// Without an owner there is no way to tell an agent's file; fail closed.
func ownerUID(os.FileInfo) (int64, bool) { return 0, false }

// linkCount is unknown here; 0 fails closed.
func linkCount(os.FileInfo) uint64 { return 0 }
