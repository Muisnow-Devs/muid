package session

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestSessionStore_JSON_roundTrip_nestedFlow(t *testing.T) {
	t.Parallel()

	// Import uuid if needed or use a helper
	opUserID := uuid.New()
	original := SessionStore{
		Attempts:        2,
		Step:            StepStart,
		Intent:          AuthIntentLinkAccount,
		OperationUserID: &opUserID,
		Flow:            &EmailOTPFlow{Email: "user@example.com"},
	}

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
	if decoded.Intent != AuthIntentLinkAccount {
		t.Fatalf("intent mismatch: expected %s, got %s", AuthIntentLinkAccount, decoded.Intent)
	}
	if decoded.OperationUserID == nil || *decoded.OperationUserID != opUserID {
		t.Fatalf("op_user_id mismatch: expected %v, got %v", opUserID, decoded.OperationUserID)
	}
	email, ok := decoded.Flow.(*EmailOTPFlow)
	if !ok || email.Email != "user@example.com" {
		t.Fatalf("email flow mismatch: ok=%v %+v", ok, email)
	}
}

func TestSessionStore_JSON_roundTrip_mailDelivery(t *testing.T) {
	t.Parallel()

	meta := SessionMetadata{
		Locale:    "zh-TW",
		Timezone:  "Asia/Taipei",
		Device:    "Chrome on macOS",
		Location:  "Taipei, TW",
		UserAgent: "Mozilla/5.0",
		IPAddress: "203.0.113.1",
	}

	original := SessionStore{
		Attempts: 1,
		Flow:     &EmailOTPFlow{Email: "user@example.com"},
		Metadata: meta,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SessionStore
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Metadata.Locale != "zh-TW" || decoded.Metadata.Timezone != "Asia/Taipei" {
		t.Fatalf(
			"mail delivery mismatch: locale=%q timezone=%q",
			decoded.Metadata.Locale,
			decoded.Metadata.Timezone,
		)
	}
	if decoded.Metadata.Device != "Chrome on macOS" || decoded.Metadata.Location != "Taipei, TW" {
		t.Fatalf(
			"login alert context: device=%q location=%q",
			decoded.Metadata.Device,
			decoded.Metadata.Location,
		)
	}
	if decoded.Metadata.UserAgent != "Mozilla/5.0" || decoded.Metadata.IPAddress != "203.0.113.1" {
		t.Fatalf(
			"login alert context: ua=%q ip=%q",
			decoded.Metadata.UserAgent,
			decoded.Metadata.IPAddress,
		)
	}
	email, ok := decoded.Flow.(*EmailOTPFlow)
	if !ok || email.Email != "user@example.com" {
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

	email, ok := decoded.Flow.(*EmailOTPFlow)
	if !ok || email.Email != "a@b.c" {
		t.Fatalf("expected legacy email flow, got ok=%v %+v", ok, email)
	}
}
