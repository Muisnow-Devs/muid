package loader

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"sanzi.io/muid/internal/gatewaypublic/graph/model"
)

func TestLoaderDedupesByID(t *testing.T) {
	t.Parallel()

	var calls int32
	l := New(func(_ context.Context, id string) (*model.Profile, error) {
		atomic.AddInt32(&calls, 1)
		return &model.Profile{ID: id}, nil
	})

	ctx := context.Background()
	// Load the same id concurrently many times; fetch must run exactly once.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := l.Load(ctx, "u1")
			if err != nil || p.ID != "u1" {
				t.Errorf("load: %v %v", p, err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 fetch for repeated id, got %d", got)
	}

	// A distinct id triggers a second fetch.
	if _, err := l.Load(ctx, "u2"); err != nil {
		t.Fatalf("load u2: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 fetches for 2 ids, got %d", got)
	}
}

func TestContextRoundTrip(t *testing.T) {
	t.Parallel()

	l := New(func(_ context.Context, id string) (*model.Profile, error) {
		return &model.Profile{ID: id}, nil
	})
	ctx := WithContext(context.Background(), l)
	got, ok := FromContext(ctx)
	if !ok || got != l {
		t.Fatalf("loader did not round-trip through context")
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatalf("empty context should not yield a loader")
	}
}
