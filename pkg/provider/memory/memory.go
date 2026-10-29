// Package memory is the reference in-memory provider. It exists to pin the
// semantics of the provider contract and to prove that the conformance suite
// passes on a correct implementation. It is not a store for real secrets.
package memory

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

type version struct {
	value    secret.Value
	created  time.Time
	disabled bool
}

// Provider is a versioned in-memory provider.
type Provider struct {
	log         *slog.Logger
	mu          sync.Mutex
	items       map[string][]*version // path -> versions, index+1 == version number
	unavailable atomic.Bool
	now         func() time.Time
}

// New returns an empty provider logging to log (nil discards).
func New(log *slog.Logger) *Provider {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Provider{log: log, items: map[string][]*version{}, now: time.Now}
}

// SetUnavailable simulates a backend outage.
func (p *Provider) SetUnavailable(down bool) { p.unavailable.Store(down) }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{Versioning: true, Write: true, Disable: true}
}

func (p *Provider) check(ctx context.Context, ref provider.Ref) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", provider.ErrUnavailable, err)
	}
	if p.unavailable.Load() {
		return fmt.Errorf("%w: memory backend switched off", provider.ErrUnavailable)
	}
	if ref.Path == "" {
		return fmt.Errorf("%w: empty path", provider.ErrInvalidRef)
	}
	return nil
}

// lookup returns the addressed version and its number. Caller holds mu.
func (p *Provider) lookup(ref provider.Ref) (*version, int, error) {
	vs := p.items[ref.Path]
	if len(vs) == 0 {
		return nil, 0, fmt.Errorf("%w: %s", provider.ErrNotFound, ref.Path)
	}
	if ref.Version == "" {
		for i := len(vs) - 1; i >= 0; i-- {
			if !vs[i].disabled {
				return vs[i], i + 1, nil
			}
		}
		return nil, 0, fmt.Errorf("%w: %s has no enabled version", provider.ErrDisabled, ref.Path)
	}
	n, err := strconv.Atoi(ref.Version)
	if err != nil || n < 1 {
		return nil, 0, fmt.Errorf("%w: version %q of %s", provider.ErrInvalidRef, ref.Version, ref.Path)
	}
	if n > len(vs) {
		return nil, 0, fmt.Errorf("%w: %s version %d", provider.ErrNotFound, ref.Path, n)
	}
	return vs[n-1], n, nil
}

func meta(v *version, n int) provider.Meta {
	return provider.Meta{Version: strconv.Itoa(n), CreatedAt: v.created, Length: v.value.Len(), Disabled: v.disabled}
}

func (p *Provider) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	if err := p.check(ctx, ref); err != nil {
		return secret.Value{}, provider.Meta{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v, n, err := p.lookup(ref)
	if err != nil {
		return secret.Value{}, provider.Meta{}, err
	}
	if v.disabled {
		return secret.Value{}, provider.Meta{}, fmt.Errorf("%w: %s version %d", provider.ErrDisabled, ref.Path, n)
	}
	p.log.Debug("resolve", "path", ref.Path, "version", n)
	return v.value.Clone(), meta(v, n), nil
}

func (p *Provider) Write(ctx context.Context, ref provider.Ref, val secret.Value) (provider.Meta, error) {
	if err := p.check(ctx, ref); err != nil {
		return provider.Meta{}, err
	}
	if ref.Version != "" {
		return provider.Meta{}, fmt.Errorf("%w: write must not name a version", provider.ErrInvalidRef)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v := &version{value: val.Clone(), created: p.now()}
	p.items[ref.Path] = append(p.items[ref.Path], v)
	n := len(p.items[ref.Path])
	p.log.Info("write", "path", ref.Path, "version", n, "length", val.Len())
	return meta(v, n), nil
}

func (p *Provider) Version(ctx context.Context, ref provider.Ref) (provider.Meta, error) {
	if err := p.check(ctx, ref); err != nil {
		return provider.Meta{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v, n, err := p.lookup(ref)
	if err != nil {
		return provider.Meta{}, err
	}
	return meta(v, n), nil
}

func (p *Provider) Disable(ctx context.Context, ref provider.Ref) error {
	if err := p.check(ctx, ref); err != nil {
		return err
	}
	if ref.Version == "" {
		return fmt.Errorf("%w: disable must name a version", provider.ErrInvalidRef)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v, n, err := p.lookup(ref)
	if err != nil {
		return err
	}
	if v.disabled {
		return nil
	}
	enabled := 0
	for _, x := range p.items[ref.Path] {
		if !x.disabled {
			enabled++
		}
	}
	if enabled == 1 {
		return fmt.Errorf("%w: %s version %d", provider.ErrLastVersion, ref.Path, n)
	}
	v.disabled = true
	v.value.Wipe()
	p.log.Info("disable", "path", ref.Path, "version", n)
	return nil
}
