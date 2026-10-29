package builtin

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Local owns one process's local root-key backend. The key is read inside
// the plaintext zone and is never returned through this factory.
type Local struct {
	pool *pgxpool.Pool
	seal *sealer.Sealer
	log  *slog.Logger
}

var errLocalKey = errors.New("builtin: local root key unavailable or insecure")

func OpenLocal(pool *pgxpool.Pool, path string, log *slog.Logger, onEvent func(KeyEvent)) (*Local, error) {
	return OpenLocalFile(pool, path, "local-v1", log, onEvent)
}

// OpenLocalFile reads and decodes the persistent root inside the plaintext
// zone. Only the ready backend leaves this factory, never key bytes. Raw
// keys are exactly 32 bytes; a 32-character base64 spelling is ambiguous
// and refused instead of being silently interpreted as a raw key.
func OpenLocalFile(pool *pgxpool.Pool, path, keyID string, log *slog.Logger, onEvent func(KeyEvent)) (*Local, error) {
	if path == "" {
		return nil, errLocalKey // persistent root required
	}
	encoded, err := readLocalRoot(path)
	if err != nil {
		return nil, errLocalKey
	}
	key := make([]byte, max(32, base64.StdEncoding.DecodedLen(len(encoded))))
	return openLocalEncoded(encoded, key, func(raw []byte) (*Local, error) {
		return NewLocal(pool, keyID, raw, log, onEvent)
	})
}

// Caller-owned buffers make both success and partial-decoding cleanup
// observable without exporting a plaintext hook. The consumer owns and
// wipes the decoded key on success; this helper wipes it on rejection.
func openLocalEncoded(encoded, key []byte, consume func([]byte) (*Local, error)) (*Local, error) {
	defer clear(encoded) // encoded root
	var n int
	if len(encoded) == 32 {
		if _, err := base64.StdEncoding.Strict().Decode(key, encoded); err == nil { // ambiguous root
			clear(key)
			return nil, errLocalKey
		}
		n = copy(key, encoded)
	} else {
		var err error
		n, err = base64.StdEncoding.Strict().Decode(key, bytes.TrimSpace(encoded))
		if err != nil {
			// Wipe even the bytes written before the decoder rejected input.
			clear(key[:])
			return nil, errLocalKey // decoded root
		}
	}
	if n != 32 {
		clear(key) // invalid root length
		return nil, errLocalKey
	}
	return consume(key[:n])
}

// NewLocal consumes and wipes key, sharing one root and Sealer between all
// providers and organization PKI in the server process. onEvent receives the
// Sealer's events (key-level changes, KEK purges); nil is refused, so a
// server never runs an administrative operation nobody journals.
func NewLocal(pool *pgxpool.Pool, keyID string, raw []byte, log *slog.Logger, onEvent func(KeyEvent)) (*Local, error) {
	defer clear(raw)
	if onEvent == nil || keyID == "" || len(raw) != 32 {
		return nil, errLocalKey
	}
	if subtle.ConstantTimeCompare(raw, make([]byte, 32)) == 1 {
		return nil, errLocalKey
	}
	root, err := sealer.NewLocalRootKey(keyID, raw)
	if err != nil {
		return nil, errLocalKey
	}
	return &Local{pool: pool, seal: sealer.New(root, eventSink(onEvent), newStore(pool)), log: log}, nil
}

// Provider selects an authenticated owner scope. The wiring layer resolves
// catalog store ids and verifies provider/status before calling this method.
func (l *Local) Provider(org, workspace, project, user string) *Provider {
	return New(l.pool, l.seal, sealer.Scope{Org: org, Workspace: workspace, Project: project, User: user}, l.log)
}

// Sealer is the zone-internal bridge used by orgpki.NewRepoFromLocal. It
// exposes cryptographic operations, never raw root-key bytes.
func (l *Local) Sealer() *sealer.Sealer { return l.seal }
