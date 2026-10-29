package api

import (
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
)

// Defaults of the catalog limit: 60 requests a minute per principal with a
// burst of 20.
const (
	defaultCatalogPerMinute = 60
	defaultCatalogBurst     = 20
	// limiterMaxBuckets bounds the memory of one limiter; past it, buckets
	// that have refilled completely (idle callers) are dropped.
	limiterMaxBuckets = 10000
)

// CatalogLimit configures the per-principal request limit on the secret
// catalog routes. The zero value means the defaults. Now is for tests.
type CatalogLimit struct {
	PerMinute int
	Burst     int
	Now       func() time.Time
}

type bucketKey struct {
	org  [16]byte
	kind identity.Kind
	id   [16]byte
}

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is a token bucket per (tenant, principal). Every request counts,
// whatever its outcome: a missing id, a foreign tenant or a policy denial
// spend the same budget as a hit, which is what stops id enumeration.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
	buckets map[bucketKey]*bucket
}

func newLimiter(c CatalogLimit) *limiter {
	if c.PerMinute <= 0 {
		c.PerMinute = defaultCatalogPerMinute
	}
	if c.Burst <= 0 {
		c.Burst = defaultCatalogBurst
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &limiter{
		rate: float64(c.PerMinute) / 60, burst: float64(c.Burst),
		now: c.Now, buckets: make(map[bucketKey]*bucket),
	}
}

// take spends one token; when none is left it returns the whole seconds
// (at least 1) until one is.
func (l *limiter) take(k bucketKey) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[k]
	if !ok {
		if len(l.buckets) >= limiterMaxBuckets {
			l.evictIdle(now)
			if len(l.buckets) >= limiterMaxBuckets {
				l.evictOldest()
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := int(math.Ceil((1 - b.tokens) / l.rate))
	if wait < 1 {
		wait = 1
	}
	return false, wait
}

// refund gives back the token take spent, up to the burst; a bucket evicted
// in between is not recreated.
func (l *limiter) refund(k bucketKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[k]; ok {
		b.tokens = math.Min(l.burst, b.tokens+1)
	}
}

func (l *limiter) evictIdle(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// evictOldest is the hard cap: when every bucket is still active, the one
// idle the longest goes.
func (l *limiter) evictOldest() {
	var oldest bucketKey
	var at time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.last.Before(at) {
			oldest, at, first = k, b.last, false
		}
	}
	if !first {
		delete(l.buckets, oldest)
	}
}

// limitMiddleware must sit after authentication. It answers 429 with a
// closed message and Retry-After; the response names no id and no value. A
// refusal is logged with the closed key set so a blocked enumeration leaves
// a trace; it names no path parameter.
func limitMiddleware(l *limiter, logger *slog.Logger, route string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := identity.FromContext(r.Context())
			requestID := reqid.FromContext(r.Context())
			if !ok {
				// Authentication always runs first; no principal is a wiring
				// error, so refuse rather than let the request through.
				writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication required", requestID)
				return
			}
			allowed, wait := l.take(bucketKey{org: p.OrgID, kind: p.Kind, id: p.ID})
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(wait))
				logger.Info("http_request",
					"method", r.Method,
					"route", route,
					"status", http.StatusTooManyRequests,
					"request_id", requestID,
					"error_class", string(apperr.ClassRateLimited),
				)
				writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited,
					"too many catalog requests; retry later", requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
