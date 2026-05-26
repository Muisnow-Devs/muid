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

func TestSessionStore_JSON_roundTrip_mailDelivery(t *testing.T) {
	t.Parallel()

	original := EmailOTPStore(StepStart, &EmailOTPFlow{Email: "user@example.com"})
	original.Locale = "zh-TW"
	original.Timezone = "Asia/Taipei"
	original.Device = "Chrome on macOS"
	original.Location = "Taipei, TW"
	original.UserAgent = "Mozilla/5.0"
	original.IPAddress = "203.0.113.1"

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SessionStore
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Locale != "zh-TW" || decoded.Timezone != "Asia/Taipei" {
		t.Fatalf("mail delivery mismatch: locale=%q timezone=%q", decoded.Locale, decoded.Timezone)
	}
	if decoded.Device != "Chrome on macOS" || decoded.Location != "Taipei, TW" {
		t.Fatalf("login alert context: device=%q location=%q", decoded.Device, decoded.Location)
	}
	if decoded.UserAgent != "Mozilla/5.0" || decoded.IPAddress != "203.0.113.1" {
		t.Fatalf("login alert context: ua=%q ip=%q", decoded.UserAgent, decoded.IPAddress)
	}
	email, ok := decoded.EmailFlow()
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

	email, ok := decoded.EmailFlow()
	if !ok || email.Email != "a@b.c" {
		t.Fatalf("expected legacy email flow, got ok=%v %+v", ok, email)
	}
}
