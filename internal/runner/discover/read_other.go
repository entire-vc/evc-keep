//go:build !unix

package discover

import (
	"context"
	"os"
)

func openRoot(string, []uint32) (*os.File, error)                               { return nil, ErrRead }
func openRelative(*os.File, string, bool, []uint32) (*os.File, error)           { return nil, ErrRead }
func readBounded(*os.File, int64) ([]byte, error)                               { return nil, ErrRead }
func expand(context.Context, *os.File, string, int, []uint32) ([]string, error) { return nil, ErrRead }
