package main

import (
	"errors"
	"io"
)

// maxServerCABytes caps the raw PEM bytes read from -server-ca. A CA bundle
// is a few KiB; anything near this limit is not one.
const maxServerCABytes = 1 << 20

var (
	errServerCAUnreadable = errors.New("-server-ca: cannot read the CA file")
	errServerCANotRegular = errors.New("-server-ca: the CA path is not a regular file")
	errServerCATooLarge   = errors.New("-server-ca: the CA file is larger than 1 MiB")
)

// readServerCAFile opens path without blocking (a FIFO with no writer would
// otherwise hang the open), checks on the SAME descriptor that it is a
// regular file (no stat-then-open race), and reads at most limit bytes,
// refusing, not truncating, a file with one byte more. Every error text is
// static: it never carries the path or any file content.
func readServerCAFile(path string, limit int64) ([]byte, error) {
	f, err := openNonBlocking(path)
	if err != nil {
		return nil, errServerCAUnreadable
	}
	defer f.Close() //nolint:errcheck // read-only descriptor
	fi, err := f.Stat()
	if err != nil {
		return nil, errServerCAUnreadable
	}
	if !fi.Mode().IsRegular() {
		return nil, errServerCANotRegular
	}
	return readLimited(f, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, errServerCAUnreadable
	}
	if int64(len(b)) > limit {
		return nil, errServerCATooLarge
	}
	return b, nil
}
