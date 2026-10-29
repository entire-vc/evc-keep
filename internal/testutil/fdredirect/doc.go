// Package fdredirect is a portable dup2 for tests and the providertest
// capture: linux/arm64 has no dup2 syscall, only dup3.
package fdredirect
