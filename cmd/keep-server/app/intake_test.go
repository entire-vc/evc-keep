package app

import (
	"strings"
	"testing"
)

func TestInputBackendConfig(t *testing.T) {
	if svc, err := newInputService(nil, nil, "", nil); err != nil || svc != nil {
		t.Fatal("disabled input backend")
	}
	for _, origin := range []string{"http://remote.example.invalid", "https://user:synthetic-password@example.invalid", "https://example.invalid/path", "https://example.invalid?query=1"} {
		if _, err := newInputService(nil, nil, origin, nil); err == nil || strings.Contains(err.Error(), origin) && origin != "" {
			t.Fatal("unsafe origin accepted or echoed")
		}
	}
}
