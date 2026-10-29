package carriers

import (
	"fmt"
	"log/slog"
)

// Metadata may contain untrusted strings before policy approval. Every
// automatic formatting/serialization path therefore redacts the whole
// descriptor, including its containing Registration and Carrier. A public
// response adapter must explicitly select approved fields from a Carrier.
func (Metadata) String() string               { return "[REDACTED]" }
func (Metadata) GoString() string             { return "[REDACTED]" }
func (Metadata) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("[REDACTED]")) }
func (Metadata) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
func (Metadata) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (Metadata) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }

// Gob does not use MarshalText. Refuse it explicitly, including promoted
// methods on Registration and Carrier, rather than serialize their fields.
func (Metadata) GobEncode() ([]byte, error)  { return nil, ErrMetadata }
func (*Metadata) GobDecode([]byte) error     { return ErrMetadata }
func (*Metadata) UnmarshalJSON([]byte) error { return ErrMetadata }
func (*Metadata) UnmarshalText([]byte) error { return ErrMetadata }
