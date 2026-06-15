package risk

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"sanzi.io/muid/pkg/shared/kv"
)

// errCorruptCounter is returned when a stored counter is not a valid integer;
// callers log it and treat the count as zero.
var errCorruptCounter = errors.New("risk: corrupt counter value")

// Tracker accumulates short-window request and auth-failure counts per
// identifier (usually client IP) in the shared kv store, supplying the
// RequestRate and AuthFailures fields of a Signal. It reuses the counter+TTL
// pattern from authn's OTP attempt limiting.
type Tracker struct {
	store         kv.KVStore
	requestWindow time.Duration
	failureWindow time.Duration
}

// TrackerConfig bounds the counting windows.
type TrackerConfig struct {
	// RequestWindow is the window over which requests are counted (default 1m).
	RequestWindow time.Duration
	// FailureWindow is the window over which auth failures are counted (default 15m).
	FailureWindow time.Duration
}

// NewTracker builds a Tracker.
func NewTracker(store kv.KVStore, cfg TrackerConfig) *Tracker {
	if cfg.RequestWindow <= 0 {
		cfg.RequestWindow = time.Minute
	}
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = 15 * time.Minute
	}
	return &Tracker{
		store:         store,
		requestWindow: cfg.RequestWindow,
		failureWindow: cfg.FailureWindow,
	}
}

// Observe records one request for identifier and returns the current request
// and failure counts within their windows.
func (t *Tracker) Observe(ctx context.Context, identifier string) (requestRate, authFailures int, err error) {
	count, err := t.incr(ctx, t.requestKey(identifier), t.requestWindow)
	if err != nil {
		return 0, 0, err
	}
	failures, err := t.read(ctx, t.failureKey(identifier))
	if err != nil {
		return 0, 0, err
	}
	return count, failures, nil
}

// RecordAuthFailure bumps the auth-failure counter for identifier.
func (t *Tracker) RecordAuthFailure(ctx context.Context, identifier string) error {
	_, err := t.incr(ctx, t.failureKey(identifier), t.failureWindow)
	return err
}

func (t *Tracker) incr(ctx context.Context, key string, window time.Duration) (int, error) {
	// Atomic INCR + first-window TTL (see kv.IncrementWithTTL): avoids leaking a
	// permanent counter when a separate Expire would have failed.
	n, err := t.store.IncrementWithTTL(ctx, key, window)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func (t *Tracker) read(ctx context.Context, key string) (int, error) {
	raw, err := t.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, kv.ErrKeyNotFound) {
			return 0, nil
		}
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, errors.Join(errCorruptCounter, err)
	}
	return n, nil
}

func (t *Tracker) requestKey(id string) string {
	return "muid:risk:req:" + id
}

func (t *Tracker) failureKey(id string) string {
	return "muid:risk:fail:" + id
}
