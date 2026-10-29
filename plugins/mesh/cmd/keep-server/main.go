// Command keep-server is Keep Server with the Mesh plugin: confirmation cards
// for approvals are created in a Mesh project. Without the KEEP_MESH_* gate
// variables it behaves exactly like the plain cmd/keep-server of the core.
package main

import (
	"os"

	"github.com/entire-vc/evc-keep/cmd/keep-server/app"
)

// options is what makes this binary the plugin build: the server asks it for
// the Mesh side of the gate.
func options() app.Options {
	return app.Options{Cards: newCards, SelfRotate: newSelfRotate, SelfRotateActor: checkSelfRotateActor}
}

func main() {
	os.Exit(app.Main(os.Args, options()))
}
