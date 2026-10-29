//go:build !darwin && !linux

package targets

// Neither macOS extended ACLs nor Linux POSIX ACLs exist on this platform
// family; there is nothing further to check beyond the mode bits and
// ownership checks that run everywhere.
func checkDirACL(int, string) error          { return nil }
func checkFileACL(int) error                 { return nil }
func checkExistingFileACL(int, string) error { return nil }
func checkAncestorACL(int, string) error     { return nil }
