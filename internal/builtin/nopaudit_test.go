package builtin

// nopAudit is the event sink of tests that never change a key level or purge.
func nopAudit(KeyEvent) {}
