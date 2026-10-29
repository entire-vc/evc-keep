//go:build !linux

package execrun

// sweepAccount has nothing to do off Linux: the allowlist is refused there and
// a none template runs only on a host that accepted the missing isolation.
func sweepAccount(uint32) error { return nil }

// accountClear has nothing to check off Linux.
func accountClear(uint32) error { return nil }

// corePipedToAHandler is false where there is no core_pattern to read.
func corePipedToAHandler() bool { return false }
