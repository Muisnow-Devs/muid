package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/pkg/gateway/ratelimit"
)

func TestLimiterAllow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := mocked.NewMockKVStore()
	lim := ratelimit.New(store, ratelimit.Config{Limit: 3, Window: time.Minute, Prefix: "test"})

	for i := 1; i <= 3; i++ {
		res, err := lim.Allow(ctx, "ip-1")
		if err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("request #%d should be allowed (count=%d)", i, res.Count)
		}
	}

	res, err := lim.Allow(ctx, "ip-1")
	if err != nil {
		t.Fatalf("Allow over limit: %v", err)
	}
	if res.Allowed {
		t.Fatalf("4th request should be blocked, got allowed (count=%d)", res.Count)
	}
	if res.RetryAfter <= 0 {
		t.Fatalf("blocked result should report RetryAfter, got %v", res.RetryAfter)
	}
}

func TestLimiterIsolatesIdentifiers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := mocked.NewMockKVStore()
	lim := ratelimit.New(store, ratelimit.Config{Limit: 1, Window: time.Minute, Prefix: "test"})

	first, err := lim.Allow(ctx, "a")
	if err != nil || !first.Allowed {
		t.Fatalf("identifier a first request should pass: allowed=%v err=%v", first.Allowed, err)
	}
	other, err := lim.Allow(ctx, "b")
	if err != nil || !other.Allowed {
		t.Fatalf("identifier b should be independent: allowed=%v err=%v", other.Allowed, err)
	}
	again, err := lim.Allow(ctx, "a")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if again.Allowed {
		t.Fatalf("identifier a second request should be blocked")
	}
}

func TestLimiterUnlimited(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := mocked.NewMockKVStore()
	lim := ratelimit.New(store, ratelimit.Config{Limit: 0, Window: time.Minute})

	for range 100 {
		res, err := lim.Allow(ctx, "ip")
		if err != nil || !res.Allowed {
			t.Fatalf("unlimited limiter must always allow: allowed=%v err=%v", res.Allowed, err)
		}
	}
}
