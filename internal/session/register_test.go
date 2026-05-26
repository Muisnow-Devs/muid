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
	if pending.Claims.Email != "user@example.com" {
		t.Fatalf("email: %q", pending.Claims.Email)
	}
	if pending.Claims.FederatedProvider != "google" || pending.Claims.FederatedSubject != "sub-1" {
		t.Fatalf("federated: %+v", pending.Claims)
	}
	if decoded.Step != StepRegister {
		t.Fatalf("step: %s", decoded.Step)
	}
}
