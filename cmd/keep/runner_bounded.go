package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Kept apart from runner.go on purpose: the pinned-main proof overlays
// runner.go, and the limit helper must still compile under that overlay.

// maxRunnerResponseBytes caps what the runner commands read from the server:
// a hostile or broken server must not be able to make the CLI buffer an
// unbounded answer.
const maxRunnerResponseBytes = 1 << 20

var errResponseTooLarge = errors.New("response body exceeds limit")

var errTrailingData = errors.New("response body is not a single JSON document")

// decodeBounded reads at most maxRunnerResponseBytes of r and decodes it as
// JSON into v. Longer input is refused with a static error; callers print
// their own static line, never the decoder's text.
func decodeBounded(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, maxRunnerResponseBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxRunnerResponseBytes {
		return errResponseTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Exactly one document: a second value or trailing garbage is refused
	// before any caller acts on the first. Trailing whitespace is io.EOF.
	if _, err := dec.Token(); err != io.EOF {
		return errTrailingData
	}
	return nil
}
