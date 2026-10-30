package meshext

import "errors"

// Mode is how a Mesh workspace uses Keep. Keep calls Mesh (hierarchy sync,
// gate cards, the gate token) only for ModeExtension; Mesh's own calls into
// Keep are served in both modes.
type Mode string

const (
	// ModeExtension is Keep installed as an extension of the workspace: Mesh
	// handed Keep an actor token and Keep calls Mesh with it.
	ModeExtension Mode = "extension"
	// ModeStore is Keep as the workspace's secret store only: Mesh calls Keep
	// through its MESH_KEEP_* settings and no Keep extension exists there.
	ModeStore Mode = "store"
)

// ErrBadMode is an installation mode other than ModeExtension or ModeStore.
var ErrBadMode = errors.New("meshext: unknown installation mode")

// Valid reports whether m is one of the two modes.
func (m Mode) Valid() bool { return m == ModeExtension || m == ModeStore }
