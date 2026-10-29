// Command keep-server is the Keep Server: the catalog of secret
// references, tenancy, policy, and the audit journal. It never stores
// or returns a secret's plaintext value over its API — see
// CONTRIBUTING.md.
//
// This is the plain build, without any tracker plugin; the server itself is
// package app, which a plugin binary calls with its own Options.
package main

import (
	"os"

	"github.com/entire-vc/evc-keep/cmd/keep-server/app"
)

func main() {
	os.Exit(app.Main(os.Args, app.Options{}))
}
