package audit

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"sanzi.io/muid/pkg/log"
)

func TestChangesStableAndOrdered(t *testing.T) {
	t.Parallel()

	before := map[string]string{"name": "old", "desc": "a"}
	after := map[string]string{"name": "new", "desc": "a"}

	got := string(Changes(before, after))
	want := `{"before":{"desc":"a","name":"old"},"after":{"desc":"a","name":"new"}}`
	if got != want {
		t.Fatalf("Changes() = %s, want %s", got, want)
	}

	// Marshalling the same input twice must be byte-identical (deterministic).
	if string(Changes(before, after)) != got {
		t.Fatal("Changes() not deterministic across calls")
	}
}

func TestChangesOmitsNilSide(t *testing.T) {
	t.Parallel()

	create := string(Changes(nil, map[string]int{"v": 1}))
	if create != `{"after":{"v":1}}` {
		t.Fatalf("create payload = %s", create)
	}
	del := string(Changes(map[string]int{"v": 1}, nil))
	if del != `{"before":{"v":1}}` {
		t.Fatalf("delete payload = %s", del)
	}
}

func TestActorRoundTrip(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	ctx := WithActor(context.Background(), id)
	got, ok := ActorFromContext(ctx)
	if !ok || got != id {
		t.Fatalf("ActorFromContext() = %v, %v; want %v, true", got, ok, id)
	}
}

func TestActorNilIsNoOp(t *testing.T) {
	t.Parallel()

	ctx := WithActor(context.Background(), uuid.Nil)
	if _, ok := ActorFromContext(ctx); ok {
		t.Fatal("nil actor should not be stored")
	}
}

func TestTraceIDFromContext(t *testing.T) {
	t.Parallel()

	if TraceID(context.Background()) != "" {
		t.Fatal("expected empty trace id on bare context")
	}
	ctx := log.With(context.Background(), "trace-123")
	if got := TraceID(ctx); got != "trace-123" {
		t.Fatalf("TraceID() = %q, want trace-123", got)
	}
}
