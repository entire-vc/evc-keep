package fdredirect

import (
	"os"
	"testing"
)

func TestDup2SameDescriptorIsNoOp(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	fd := int(f.Fd())
	if err := Dup2(fd, fd); err != nil {
		t.Fatalf("Dup2(fd, fd) = %v, want nil", err)
	}
}

func TestDup2SameInvalidDescriptorFails(t *testing.T) {
	if err := Dup2(1<<20, 1<<20); err == nil {
		t.Fatal("Dup2 on an invalid descriptor returned nil, want EBADF")
	}
}
