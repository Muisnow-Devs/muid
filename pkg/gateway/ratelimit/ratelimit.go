// Package ratelimit provides a fixed-window request limiter backed by the
// shared kv store. It mirrors the counter+TTL pattern used by authn's OTP
// cooldowns (internal/authn/kv/otp_store.go) so gateways do not invent a
// parallel mechanism.
package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sanzi.io/muid/pkg/shared/kv"
)

// Config bounds a fixed window.
type Config struct {
	// Limit is the maximum number of requests permitted per Window.
	Limit int64
	// Window is the rolling fixed window duration.
	Window time.Duration
	// Prefix namespaces the keys (e.g. the gateway name); defaults to "default".
	Prefix string
}

// Limiter enforces a fixed-window quota per identifier.
type Limiter struct {
	store  kv.KVStore
	limit  int64
	window time.Duration
	prefix string
}

// New builds a Limiter. limit<=0 yields an effectively-unlimited limiter that
// always allows; window<=0 defaults to one minute.
func New(store kv.KVStore, cfg Config) *Limiter {
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	prefix := strings.TrimSpace(cfg.Prefix)
	if prefix == "" {
		prefix = "default"
	}
	return &Limiter{
		store:  store,
		limit:  cfg.Limit,
		window: cfg.Window,
		prefix: prefix,
	}
}

// Result reports the outcome of an Allow check.
type Result struct {
	Allowed    bool
	Count      int64
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
}

// Allow records one request for identifier and reports whether it stays within
// the window quota. The first request of a window sets the key's expiry.
func (l *Limiter) Allow(ctx context.Context, identifier string) (Result, error) {
	if l.limit <= 0 {
		return Result{Allowed: true, Limit: l.limit}, nil
	}

	key := l.key(identifier)
	// Atomic INCR + first-window TTL: a non-atomic increment-then-expire could
	// leave a permanent counter with no TTL if the expire failed.
	count, err := l.store.IncrementWithTTL(ctx, key, l.window)
	if err != nil {
		return Result{}, err
	}

	res := Result{
		Count:   count,
		Limit:   l.limit,
		Allowed: count <= l.limit,
	}
	if remaining := l.limit - count; remaining > 0 {
		res.Remaining = remaining
	}
	if !res.Allowed {
		if ttl, ttlErr := l.store.TTL(ctx, key); ttlErr == nil && ttl > 0 {
			res.RetryAfter = ttl
		} else {
			res.RetryAfter = l.window
		}
	}
	return res, nil
}

func (l *Limiter) key(identifier string) string {
	return fmt.Sprintf("muid:ratelimit:%s:%s", l.prefix, identifier)
}
