package main

import "github.com/entire-vc/evc-keep/internal/builtin"

// nopAudit is the event sink of tests that never change a key level or purge.
func nopAudit(builtin.KeyEvent) {}
