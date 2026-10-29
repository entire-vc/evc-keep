// Package svctoken keeps a service token (for example the Mesh account of
// the rotation plugin) in a Provider's sealed store. It sits in the plaintext
// zone because the token has to become the text of an Authorization header,
// and that is the only place its bytes are read.
//
// The token lives under one secret name. A new token is first staged under a
// name of its own (name + "-staged-" + key id), so a half-finished rotation
// never changes what Token returns; Activate then writes it as the next
// version of the main name and erases the staged copies, so a live token has
// one sealed copy. Nothing here logs, formats or returns a value
// except Token, whose result the caller puts into a request header and drops.
package svctoken

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// ErrConfig: an unusable provider or secret name.
var ErrConfig = errors.New("svctoken: invalid configuration")

// ErrKeyID: a key id that is not a canonical lowercase UUID.
var ErrKeyID = errors.New("svctoken: invalid key id")

// ErrDiscarded: the staged value of this key id was discarded by this Store.
var ErrDiscarded = errors.New("svctoken: staged value was discarded")

// ErrStagedCleanup: the staged copies were not dropped for a reason outside
// the provider error classes.
var ErrStagedCleanup = errors.New("svctoken: staged cleanup failed")

// ErrStagedLeft: staged versions were still there after the cleanup bound.
var ErrStagedLeft = errors.New("svctoken: staged versions left after cleanup")

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Store holds one service token in p. Its methods are safe for concurrent use.
type Store struct {
	p    provider.Provider
	name string

	mu     sync.Mutex
	staged map[string][]string // key id -> versions written by Stage
	onLeft func(error)
}

// eraser is the crypto-erasure of one version, which the builtin provider has.
// A provider without it gets its staged versions disabled instead.
type eraser interface {
	Erase(ctx context.Context, ref provider.Ref) error
}

// maxStagedVersions bounds the staged versions Activate drops after a restart,
// when it learns them one by one from the provider.
const maxStagedVersions = 16

// cleanupTimeout bounds the drop of staged copies. It runs on a context that
// outlives the caller's: once the token is switched nothing retries it.
const cleanupTimeout = 30 * time.Second

// New returns a Store for the secret called name.
func New(p provider.Provider, name string) (*Store, error) {
	if p == nil || !namePattern.MatchString(name) {
		return nil, ErrConfig
	}
	return &Store{p: p, name: name, staged: map[string][]string{}}, nil
}

func (s *Store) main() provider.Ref { return provider.Ref{Path: "builtin://" + s.name} }

func (s *Store) droppedRef(keyID string) provider.Ref {
	return provider.Ref{Path: "builtin://" + s.name + "-dropped-" + keyID}
}

func (s *Store) stagedRef(keyID string) provider.Ref {
	return provider.Ref{Path: "builtin://" + s.name + "-staged-" + keyID}
}

// Stage seals v under the staged name of keyID. The value is not the token
// yet: Token keeps returning the previous one.
func (s *Store) Stage(ctx context.Context, keyID string, v secret.Value) error {
	if !rotation.ValidKeyID(keyID) {
		return ErrKeyID
	}
	if v.IsZero() {
		return ErrConfig
	}
	m, err := s.p.Write(ctx, s.stagedRef(keyID), v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.staged[keyID] = append(s.staged[keyID], m.Version)
	s.mu.Unlock()
	return nil
}

// CanErase reports whether the provider crypto-erases staged copies.
func (s *Store) CanErase() bool {
	_, ok := s.p.(eraser)
	return ok
}

// OnStagedLeft sets fn to hear about staged copies Activate could not drop. fn
// gets a bare class: ErrStagedLeft, a provider error class, or
// ErrStagedCleanup. A provider's own error text never reaches it.
func (s *Store) OnStagedLeft(fn func(error)) {
	s.mu.Lock()
	s.onLeft = fn
	s.mu.Unlock()
}

// Activate makes the staged value of keyID the token: it becomes the newest
// version of the main name, and the staged copies are dropped.
func (s *Store) Activate(ctx context.Context, keyID string) error {
	if !rotation.ValidKeyID(keyID) {
		return ErrKeyID
	}
	// A provider cannot disable the last enabled version of a name, so a
	// discarded value may stay resolvable: Activate refuses it through the mark
	// Discard wrote, which survives a restart.
	if mv, _, err := s.p.Resolve(ctx, s.droppedRef(keyID)); err == nil {
		mv.Wipe()
		return ErrDiscarded
	} else if !errors.Is(err, provider.ErrNotFound) {
		return err
	}
	v, _, err := s.p.Resolve(ctx, s.stagedRef(keyID))
	if err != nil {
		return err
	}
	defer v.Wipe()
	if _, err := s.p.Write(ctx, s.main(), v); err != nil {
		return err
	}
	s.dropStaged(ctx, keyID)
	return nil
}

// dropStaged erases the staged versions of keyID once its value is the token.
// The token is already switched, so a failure is only reported: an Activate
// error would make the rotation revoke the key the token now holds.
func (s *Store) dropStaged(ctx context.Context, keyID string) {
	s.mu.Lock()
	versions := s.staged[keyID]
	delete(s.staged, keyID)
	report := s.onLeft
	s.mu.Unlock()
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if err := s.dropVersions(bg, keyID, versions); err != nil && report != nil {
		report(leftClass(err))
	}
}

// leftClass strips a cleanup error down to its class, so the text a provider
// put into it stays here.
func leftClass(err error) error {
	if errors.Is(err, ErrStagedLeft) {
		return ErrStagedLeft
	}
	if c := provider.Class(err); c != nil {
		return c
	}
	return ErrStagedCleanup
}

func (s *Store) dropVersions(ctx context.Context, keyID string, versions []string) error {
	for i := len(versions) - 1; i >= 0; i-- {
		if err := s.drop(ctx, keyID, versions[i]); errors.Is(err, provider.ErrLastVersion) {
			return nil
		} else if err != nil {
			return err
		}
	}
	// A restarted Store remembers no versions: ask for the newest one, without
	// opening it, until none is left. A provider that only disables stops at
	// the last enabled version. A version still there past the bound is
	// reported, never taken for a clean store.
	for i := 0; ; i++ {
		m, err := s.p.Version(ctx, s.stagedRef(keyID))
		if errors.Is(err, provider.ErrNotFound) || errors.Is(err, provider.ErrDisabled) {
			return nil
		}
		if err != nil {
			return err
		}
		if i == maxStagedVersions {
			return ErrStagedLeft
		}
		if err := s.drop(ctx, keyID, m.Version); errors.Is(err, provider.ErrLastVersion) {
			return nil
		} else if err != nil {
			return err
		}
	}
}

// drop erases one staged version, or disables it on a provider without
// erasure. An absent version is already dropped. ErrLastVersion is returned
// for the caller to stop on.
func (s *Store) drop(ctx context.Context, keyID, version string) error {
	ref := s.stagedRef(keyID)
	ref.Version = version
	var err error
	if e, ok := s.p.(eraser); ok {
		err = e.Erase(ctx, ref)
	} else {
		err = s.p.Disable(ctx, ref)
	}
	if errors.Is(err, provider.ErrNotFound) {
		return nil
	}
	return err
}

// Discard drops the staged value of keyID: Activate refuses it from now on and
// the provider is asked to disable its versions. A provider refuses to disable
// the last enabled version of a name; that refusal is not an error here: the
// sealed copy belongs to a key Mesh no longer honours.
func (s *Store) Discard(ctx context.Context, keyID string) error {
	if !rotation.ValidKeyID(keyID) {
		return ErrKeyID
	}
	s.mu.Lock()
	versions := s.staged[keyID]
	delete(s.staged, keyID)
	s.mu.Unlock()
	// Persist the discard before the versions are disabled. The mark holds no
	// token, only a constant byte.
	if _, err := s.p.Write(ctx, s.droppedRef(keyID), secret.New([]byte{1})); err != nil {
		return err
	}
	for _, ver := range versions {
		ref := s.stagedRef(keyID)
		ref.Version = ver
		err := s.p.Disable(ctx, ref)
		if err != nil && !errors.Is(err, provider.ErrLastVersion) && !errors.Is(err, provider.ErrNotFound) {
			return err
		}
	}
	return nil
}

// Seed seals v as the token when the Store holds none yet and reports whether
// it did. An existing token is never replaced: a restart with the bootstrap
// file still in place must not undo a rotation. The Meta carries the version
// and length only.
func (s *Store) Seed(ctx context.Context, v secret.Value) (provider.Meta, bool, error) {
	if v.IsZero() {
		return provider.Meta{}, false, ErrConfig
	}
	cur, _, err := s.p.Resolve(ctx, s.main())
	if err == nil {
		cur.Wipe()
		return provider.Meta{}, false, nil
	}
	if !errors.Is(err, provider.ErrNotFound) {
		return provider.Meta{}, false, err
	}
	m, err := s.p.Write(ctx, s.main(), v)
	if err != nil {
		return provider.Meta{}, false, err
	}
	return m, true, nil
}

// Has reports whether the Store already holds a token. It reads nothing but
// the answer: the value is wiped at once.
func (s *Store) Has(ctx context.Context) (bool, error) {
	cur, _, err := s.p.Resolve(ctx, s.main())
	if err == nil {
		cur.Wipe()
		return true, nil
	}
	if errors.Is(err, provider.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// Token returns the current token as text for one request header. The caller
// must not keep, log or format it. A missing token is provider.ErrNotFound.
func (s *Store) Token(ctx context.Context) (string, error) {
	v, _, err := s.p.Resolve(ctx, s.main())
	if err != nil {
		return "", err
	}
	defer v.Wipe()
	var tok string
	secret.Expose(v, func(b []byte) { tok = string(b) })
	if tok == "" {
		return "", fmt.Errorf("%w: empty token", provider.ErrNotFound)
	}
	return tok, nil
}
