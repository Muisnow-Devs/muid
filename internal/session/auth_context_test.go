package session

import "testing"

func TestSessionStore_AuthContext_roundTrip(t *testing.T) {
	t.Parallel()

	store := OIDCStore(StepStart, &OIDCFlow{
		OAuthState:       "state",
		PKCECodeVerifier: "verifier",
	}).WithAuthContext("link_account", "550e8400-e29b-41d4-a716-446655440000").
		WithLinkSessionWire("selector.validator")

	intent, linkUserID, ok := store.AuthContext()
	if !ok || intent != "link_account" || linkUserID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("auth context: intent=%q link=%q ok=%v", intent, linkUserID, ok)
	}
	if store.LinkSessionWire != "selector.validator" {
		t.Fatalf("link session wire: %q", store.LinkSessionWire)
	}

	oidc, ok := store.OIDCFlowState()
	if !ok || oidc.OAuthState != "state" || oidc.PKCECodeVerifier != "verifier" {
		t.Fatalf("oidc flow ceremony state: %+v", oidc)
	}
}
