//go:build !unix

package builtin

func readLocalRoot(string) ([]byte, error) { return nil, errLocalKey }
