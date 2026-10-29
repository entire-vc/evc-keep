//go:build !linux

package execrun

import (
	"errors"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

// Enforces is false off Linux: there is no namespace to put a child in.
func (n *Netns) Enforces(mode execpolicy.NetMode) bool { return false }

// Prepare always refuses; Run never calls it because Enforces is false.
func (n *Netns) Prepare(mode execpolicy.NetMode, pins []Pin) ([]string, func(), error) {
	return nil, nil, errors.New("netns: not supported on this OS")
}

// Sweep has nothing to remove off Linux.
func (n *Netns) Sweep() {}
