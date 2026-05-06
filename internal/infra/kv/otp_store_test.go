package kv

import (
	"context"
	"testing"
	"time"

	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/pkg/shared/infra/mocked"
)

func TestKVOTPStore_SetAndVerify_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"
	code := "123456"

	err := store.SetOTP(ctx, session, code, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	valid, err := store.VerifyOTP(ctx, session, code)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !valid {
		t.Error("expected OTP to be valid")
	}

	// Verify should revoke after success (single-use)
	valid, err = store.VerifyOTP(ctx, session, code)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if valid {
		t.Error("expected OTP to be invalid/revoked after first use")
	}
}

func TestKVOTPStore_Verify_IncorrectCode(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"
	code := "123456"

	_ = store.SetOTP(ctx, session, code, 5*time.Minute)

	valid, err := store.VerifyOTP(ctx, session, "wrong-code")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if valid {
		t.Error("expected OTP to be invalid for wrong code")
	}
}

func TestKVOTPStore_Verify_NotFound(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	valid, err := store.VerifyOTP(ctx, "non-existent", "123456")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if valid {
		t.Error("expected OTP to be invalid when not found")
	}
}

func TestKVOTPStore_Security_BruteForceProtection(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"
	code := "123456"
	_ = store.SetOTP(ctx, session, code, 5*time.Minute)

	// Attempt 1: Fail
	valid, err := store.VerifyOTP(ctx, session, "000001")
	if err != nil {
		t.Fatalf("expected no error on 1st attempt, got %v", err)
	}
	if valid {
		t.Fatal("expected invalid code to fail")
	}

	// Attempt 2: Fail
	valid, err = store.VerifyOTP(ctx, session, "000002")
	if err != nil {
		t.Fatalf("expected no error on 2nd attempt, got %v", err)
	}
	if valid {
		t.Fatal("expected invalid code to fail")
	}

	// Attempt 3: Fail & Revoke (Too many attempts)
	valid, err = store.VerifyOTP(ctx, session, "000003")
	if err != otp.ErrTooManyAttempts {
		t.Fatalf("expected ErrTooManyAttempts on 3rd fail, got %v", err)
	}
	if valid {
		t.Fatal("expected invalid code to fail")
	}

	// Attempt 4: Should act like Not Found / Already Revoked, even with correct code
	valid, err = store.VerifyOTP(ctx, session, code)
	if err != nil {
		t.Fatalf("expected no error when not found, got %v", err)
	}
	if valid {
		t.Fatal("expected true code to fail because session should have been revoked")
	}
}

func TestKVOTPStore_Verify_Expired(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"
	code := "123456"

	// Set with a negative duration to simulate expiration
	_ = store.SetOTP(ctx, session, code, -1*time.Minute)

	valid, err := store.VerifyOTP(ctx, session, code)
	if err != nil {
		t.Fatalf("expected no error (just invalid), got %v", err)
	}
	if valid {
		t.Error("expected OTP to be invalid due to expiration")
	}
}

func TestKVOTPStore_Revoke_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"
	code := "123456"
	_ = store.SetOTP(ctx, session, code, 5*time.Minute)

	err := store.RevokeOTP(ctx, session)
	if err != nil {
		t.Fatalf("expected no error on revoke, got %v", err)
	}

	valid, err := store.VerifyOTP(ctx, session, code)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if valid {
		t.Error("expected OTP to be invalid after revocation")
	}
}
