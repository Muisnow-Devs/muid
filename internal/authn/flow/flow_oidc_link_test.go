package flow

import (
	"context"
	"testing"

	"sanzi.io/muid/infra/mocked"
	authnkv "sanzi.io/muid/internal/authn/kv"
	"sanzi.io/muid/internal/identity"
)

func TestMapContinueError_OIDCManualLinkRequired(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	svc := &Service{transitionStore: store}
	resp, err := svc.mapContinueError(ctx, "tid-1", identity.ErrOIDCManualAccountLinkingRequired)
	if err != nil {
		t.Fatalf("mapContinueError: %v", err)
	}
	fail := resp.GetAuthFailure()
	if fail == nil {
		t.Fatal("expected auth failure")
	}
	want := "This email is already registered without this OIDC provider. Manual account linking is required."
	if fail.GetReason() != want {
		t.Fatalf("reason: got %q want %q", fail.GetReason(), want)
	}
	if fail.GetErrorCode() != ErrCodeOIDCManualLinkRequired {
		t.Fatalf("error_code: got %q want %q", fail.GetErrorCode(), ErrCodeOIDCManualLinkRequired)
	}
}
