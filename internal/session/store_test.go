package session

import (
	"encoding/json"
	"testing"
)

func TestSessionStore_JSON_roundTrip_nestedFlow(t *testing.T) {
	t.Parallel()

	original := EmailOTPStore(StepStart, &EmailOTPFlow{
		Email:  "user@example.com",
		Intent: "login",
	})
	original.Attempts = 2

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SessionStore
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Attempts != 2 || decoded.Step != StepStart {
		t.Fatalf("metadata mismatch: %+v", decoded)
	}
	email, ok := decoded.EmailFlow()
	if !ok || email.Email != "user@example.com" || email.Intent != "login" {
		t.Fatalf("email flow mismatch: ok=%v %+v", ok, email)
	}
}

func TestSessionStore_JSON_legacyFlatFlowKind(t *testing.T) {
	t.Parallel()

	legacy := `{"attempts":1,"step":"start","flow":"email_otp","email":{"email":"a@b.c","intent":"login"}}`

	var decoded SessionStore
	err := json.Unmarshal([]byte(legacy), &decoded)
	if err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}

	email, ok := decoded.EmailFlow()
	if !ok || email.Email != "a@b.c" {
		t.Fatalf("expected legacy email flow, got ok=%v %+v", ok, email)
	}
}
