package kv

import (
	"context"
	"testing"
	"time"

	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/pkg/shared/infra/mocked"
)

func TestKVOTPStore_CreateAndVerify_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"

	code, err := store.CreateOTP(ctx, session, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = store.VerifyOTP(ctx, session, code)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify should revoke after success (single-use)
	err = store.VerifyOTP(ctx, session, code)
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid after first use, got %v", err)
	}
}

func TestKVOTPStore_Verify_IncorrectCode(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"

	_, err := store.CreateOTP(ctx, session, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = store.VerifyOTP(ctx, session, "000000") // 6 digits wrong code
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid for wrong code, got %v", err)
	}
}

func TestKVOTPStore_Verify_NotFound(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	err := store.VerifyOTP(ctx, "non-existent", "123456")
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid when not found, got %v", err)
	}
}

func TestKVOTPStore_Security_BruteForceProtection(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"
	code, err := store.CreateOTP(ctx, session, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}
	if code == "000001" || code == "000002" || code == "000003" {
		t.Skip("accidentally generated code used in test, skip")
	}

	// Attempt 1: Fail
	err = store.VerifyOTP(ctx, session, "000001")
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid on 1st attempt, got %v", err)
	}

	// Attempt 2: Fail
	err = store.VerifyOTP(ctx, session, "000002")
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid on 2nd attempt, got %v", err)
	}

	// Attempt 3: Fail & Revoke (Too many attempts)
	err = store.VerifyOTP(ctx, session, "000003")
	if err != otp.ErrTooManyAttempts {
		t.Fatalf("expected ErrTooManyAttempts on 3rd fail, got %v", err)
	}

	// Attempt 4: Should act like Not Found / Already Revoked, even with correct code
	err = store.VerifyOTP(ctx, session, code)
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid when not found, got %v", err)
	}
}

func TestKVOTPStore_Verify_Expired(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"

	// Set with a negative duration to simulate expiration
	code, err := store.CreateOTP(ctx, session, -1*time.Minute)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = store.VerifyOTP(ctx, session, code)
	if err != otp.ErrOTPExpired {
		t.Fatalf("expected ErrOTPExpired, got %v", err)
	}
}

func TestKVOTPStore_Revoke_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"))
	ctx := context.Background()

	session := "session-123"
	code, err := store.CreateOTP(ctx, session, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = store.RevokeOTP(ctx, session)
	if err != nil {
		t.Fatalf("expected no error on revoke, got %v", err)
	}

	err = store.VerifyOTP(ctx, session, code)
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid after revocation, got %v", err)
	}
}
