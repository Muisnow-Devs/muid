package session

import (
	"encoding/json"
	"testing"

	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
)

func TestRegisterPending_JSON_roundTrip(t *testing.T) {
	t.Parallel()

	claims := &claimspb.IdentityInformation{}
	claims.SetEmail("User@Example.com")
	claims.SetEmailVerified(true)
	claims.SetFederatedProvider("google")
	claims.SetFederatedSubject("sub-1")

	original := EmailOTPStore(StepRegister, &EmailOTPFlow{Email: "user@example.com"}).
		WithRegisterPending(RegisterPendingClaimsFromProto(claims))
	original = original.WithProvisionedUserID("550e8400-e29b-41d4-a716-446655440000")

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SessionStore
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	pending, ok := decoded.PendingRegisterState()
	if !ok {
		t.Fatal("expected pending register")
	}
	if pending.ProvisionedUserID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("provisioned id: %q", pending.ProvisionedUserID)
	}
	if pending.Claims.Email != "user@example.com" {
		t.Fatalf("email: %q", pending.Claims.Email)
	}
	if pending.Claims.FederatedProvider != "google" || pending.Claims.FederatedSubject != "sub-1" {
		t.Fatalf("federated: %+v", pending.Claims)
	}
	if decoded.Step != StepFinish {
		t.Fatalf("step: %s", decoded.Step)
	}
}
