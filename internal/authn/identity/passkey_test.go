package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/authn/account"
	authnkv "sanzi.io/muid/internal/authn/kv"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

func TestPasskeyStartLogin_usesWebAuthnRequestOptionsAndSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	transitions := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	provider := NewPasskeyIdentityProvider(transitions, nil, nil, nil)

	step, err := provider.Start(ctx, idn.StartInput{Intent: idn.IntentLogin})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	if step.Type != idn.StepChallenge || step.Payload == nil || step.Payload.Passkey == nil {
		t.Fatalf("step payload: %+v", step)
	}

	payload := step.Payload.Passkey
	if payload.Ceremony != PasskeyCeremonyAuthentication {
		t.Fatalf("ceremony: %q", payload.Ceremony)
	}
	if payload.PublicKeyCredentialCreationOptionsJSON != "" {
		t.Fatalf("unexpected creation options: %s", payload.PublicKeyCredentialCreationOptionsJSON)
	}

	var options struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
	}
	if err := json.Unmarshal([]byte(payload.PublicKeyCredentialRequestOptionsJSON), &options); err != nil {
		t.Fatalf("request options json: %v", err)
	}
	if options.Challenge == "" || options.RPID != "localhost" ||
		options.UserVerification != "preferred" {
		t.Fatalf("options: %+v", options)
	}

	stored, err := transitions.Get(ctx, step.TransitionId)
	if err != nil {
		t.Fatalf("load transition: %v", err)
	}
	flow, ok := stored.Store.PasskeyFlowState()
	if !ok {
		t.Fatal("expected passkey flow")
	}
	if flow.Ceremony != PasskeyCeremonyAuthentication {
		t.Fatalf("stored ceremony: %q", flow.Ceremony)
	}
	if flow.Session.Challenge != options.Challenge || flow.Session.RelyingPartyID != "localhost" {
		t.Fatalf("stored session: %+v", flow.Session)
	}

	data, err := json.Marshal(stored.Store)
	if err != nil {
		t.Fatalf("marshal store: %v", err)
	}
	var roundTrip session.SessionStore
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("unmarshal store: %v", err)
	}
	roundTripFlow, ok := roundTrip.PasskeyFlowState()
	if !ok || roundTripFlow.Session.Challenge != options.Challenge {
		t.Fatalf("round trip flow: ok=%v %+v", ok, roundTripFlow)
	}
}

func TestPasskeyDiscoverableUserHandler_rejectsUserHandleMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openRegisterFinishTestDB(t)
	owner := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	other := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	seedRegisterFinishUserRef(t, db, owner, "owner@example.com")
	seedRegisterFinishUserRef(t, db, other, "other@example.com")

	credentialID := []byte("credential-id")
	err := db.UserPasskey.Create().
		SetUserID(owner).
		SetCredentialID(credentialID).
		SetPublicKey([]byte("public-key")).
		SetRpID("localhost").
		SetDeviceType("multi_device").
		SetName("Passkey").
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed passkey: %v", err)
	}

	store := &account.Store{DB: db}
	_, _, _, _, passkeys, sessions, _ := account.Wire(store, nil, "")
	provider := NewPasskeyIdentityProvider(
		authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore()),
		passkeys,
		sessions,
		nil,
	).(*PasskeyProvider)

	_, err = provider.discoverableUserHandler(ctx)(credentialID, other[:])
	if !errors.Is(err, idn.ErrInvalidSessionState) {
		t.Fatalf("expected invalid session state, got %v", err)
	}
}
