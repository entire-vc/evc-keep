//go:build !unix

package main

import "os"

func fileOwner(os.FileInfo) (int, bool) { return 0, false }
