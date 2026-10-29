// Package closedschema deliberately does not compile. It exists only to be
// built as a subprocess by ../../record_test.go's
// TestClosedSchemaFieldDoesNotCompile — see that test for why.
//
// This file lives under a directory literally named "testdata": Go's own
// tooling (go build/vet/test) skips any directory named testdata when
// walking "./..." — the standard way to keep intentionally-broken source
// out of every other build/vet/lint step in this repo (`go build ./...`,
// CI's fmt-vet job, golangci-lint) while still being reachable by an
// explicit path, which is exactly what the test needs.
package closedschema

import "github.com/entire-vc/evc-keep/internal/audit"

// This must NOT compile: Record has no field named CanaryValue — the whole
// point of a closed schema (record.go's doc) is that there is nowhere for a
// value to go except the fields the threat model's §4.2 actually lists.
var _ = audit.Record{
	CanaryValue: "kc-canary-should-not-compile",
}
