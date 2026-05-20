package log

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestProfileID_fullUUID(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	a := ProfileID(id)
	if a.Key != "profile_id" || a.Value.String() != id.String() {
		t.Fatalf("attr: got %v=%v", a.Key, a.Value)
	}
}

func TestUserID_fullUUID(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("0194a2b3-c4d5-7890-abcd-ef1234567890")
	a := UserID(id)
	if a.Key != "user_id" || a.Value.String() != id.String() {
		t.Fatalf("attr: got %v=%v", a.Key, a.Value)
	}
}

func TestTransitionID_fullUUID(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("0194a2b3-c4d5-7890-abcd-ef1234567891")
	a := TransitionID(id)
	if a.Key != "transition_id" || a.Value.String() != id.String() {
		t.Fatalf("attr: got %v=%v", a.Key, a.Value)
	}
}

func TestWithAttrs_mergesProfileID(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	ctx := WithAttrs(context.Background(), ProfileID(id))
	attrs := attrsFromContext(ctx)
	if len(attrs) != 1 || attrs[0].Key != "profile_id" {
		t.Fatalf("attrs: %+v", attrs)
	}
}
