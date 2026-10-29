package descriptor

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDescriptorCanonicalFields(t *testing.T) {
	m := Metadata{"name<&\u00e9", "org:scope", "storage", "dev", "user requester", "sponsor"}
	public := make([]byte, 32)
	message := Message("request", public, m)
	const domain = "keep/intake-key/v2\x00"
	if !bytes.HasPrefix(message, []byte(domain)) {
		t.Fatal("descriptor domain is not the fixed v2 NUL-terminated prefix")
	}
	message = message[len(domain):]
	fields := []string{"request", string(public), m.SecretName, m.Scope, m.StoreName, m.Class, m.RequestedBy, m.Sponsor}
	for _, field := range fields {
		if len(message) < 4 || int64(binary.BigEndian.Uint32(message[:4])) != int64(len(field)) {
			t.Fatal("missing UTF-8 byte length prefix")
		}
		message = message[4:]
		if len(message) < len(field) || string(message[:len(field)]) != field {
			t.Fatal("unexpected canonical field order or encoding")
		}
		message = message[len(field):]
	}
	if len(message) != 0 {
		t.Fatal("unexpected trailing descriptor data")
	}
	m.Sponsor = ""
	empty := Message("request", public, m)
	expectedLength := len(domain)
	for _, field := range []string{"request", string(public), m.SecretName, m.Scope, m.StoreName, m.Class, m.RequestedBy, m.Sponsor} {
		expectedLength += 4 + len(field)
	}
	if len(empty) != expectedLength || !bytes.Equal(empty[len(empty)-4:], []byte{0, 0, 0, 0}) {
		t.Fatal("empty sponsor lacks its zero length prefix")
	}
	if bytes.Equal(Message("request", public, Metadata{SecretName: "ab", Scope: "c"}), Message("request", public, Metadata{SecretName: "a", Scope: "bc"})) {
		t.Fatal("ambiguous metadata boundary")
	}
}
