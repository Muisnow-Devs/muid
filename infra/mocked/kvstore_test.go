package mocked

import (
	"context"
	"testing"
	"time"
)

func TestIncrementWithTTL(t *testing.T) {
	t.Parallel()

	store := NewMockKVStore()
	ctx := context.Background()
	const key = "counter"

	// First increment creates the key with value 1 and applies the TTL.
	n, err := store.IncrementWithTTL(ctx, key, time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("first increment = %d, err %v; want 1", n, err)
	}
	ttl, err := store.TTL(ctx, key)
	if err != nil || ttl <= 0 {
		t.Fatalf("expected a positive TTL after first increment, got %v err %v", ttl, err)
	}

	// Subsequent increments do not reset the TTL (fixed-window semantics).
	n, err = store.IncrementWithTTL(ctx, key, time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("second increment = %d, err %v; want 2", n, err)
	}
	if ttl2, _ := store.TTL(ctx, key); ttl2 > time.Minute {
		t.Fatalf("TTL must not be extended on later increments, got %v", ttl2)
	}
}

func TestIncrementWithTTLSelfHealsMissingExpiry(t *testing.T) {
	t.Parallel()

	store := NewMockKVStore()
	ctx := context.Background()
	const key = "counter"

	// A plain Increment leaves the key without an expiry (the non-atomic hazard).
	if _, err := store.Increment(ctx, key); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if ttl, _ := store.TTL(ctx, key); ttl != -1 {
		t.Fatalf("expected no expiry, got %v", ttl)
	}

	// IncrementWithTTL applies a TTL when the key currently has none.
	if _, err := store.IncrementWithTTL(ctx, key, time.Minute); err != nil {
		t.Fatalf("increment with ttl: %v", err)
	}
	if ttl, _ := store.TTL(ctx, key); ttl <= 0 {
		t.Fatalf("expected a TTL to be applied, got %v", ttl)
	}
}
