//go:build unix

package targets

import (
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// fileHandler writes the value as-is: the target's whole content is the
// value, nothing else.
type fileHandler struct{}

func (fileHandler) foldsExisting() bool { return false }

func (fileHandler) build(_ []byte, _ bool, _ runnerproto.Target, v secret.Value) ([]byte, error) {
	return bytesOf(v), nil
}

func (fileHandler) readBack(content []byte, _ runnerproto.Target) (secret.Value, error) {
	return secret.New(content), nil
}
