package main

import (
	"errors"
	"io"
)

// maxPolicyFileBytes caps the raw bytes read from a -policy file. A policy
// is a small config document; the cap keeps a hostile or mistaken path from
// pulling unbounded data into memory before validation.
const maxPolicyFileBytes = 1 << 20

var errPolicyFileUnreadable = errors.New("policy file unreadable")

// readPolicyFile reads the operator-supplied policy file without blocking
// and without trusting the path's type: the file is opened non-blocking,
// checked to be a regular file on the SAME descriptor it then reads (a
// stat-then-open pair would race), and read under a limit+1 cap so an
// oversized file is refused rather than truncated. Every failure returns
// the same static error: the path and any file bytes never appear in it.
func readPolicyFile(path string) ([]byte, error) {
	f, err := openPolicyFile(path)
	if err != nil {
		return nil, errPolicyFileUnreadable
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, errPolicyFileUnreadable
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPolicyFileBytes+1))
	if err != nil || len(b) > maxPolicyFileBytes {
		return nil, errPolicyFileUnreadable
	}
	return b, nil
}
