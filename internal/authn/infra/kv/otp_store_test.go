package kv

import (
	"context"
	"errors"
	"testing"
	"time"

	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/otp"
)

func TestKVOTPStore_CreateAndVerify_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), 0)
	ctx := context.Background()

	session := "session-123"

	code, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = store.VerifyOTP(ctx, session, code.OTP)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify should revoke after success (single-use)
	err = store.VerifyOTP(ctx, session, code.OTP)
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid after first use, got %v", err)
	}
}

func TestKVOTPStore_Verify_IncorrectCode(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), 0)
	ctx := context.Background()

	session := "session-123"

	_, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
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
	store := NewKVOTPStore(mockKV, []byte("super-secret"), 0)
	ctx := context.Background()

	err := store.VerifyOTP(ctx, "non-existent", "123456")
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid when not found, got %v", err)
	}
}

func TestKVOTPStore_Security_BruteForceProtection(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), 0)
	ctx := context.Background()

	session := "session-123"
	code, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}
	if code.OTP == "000001" || code.OTP == "000002" || code.OTP == "000003" {
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
	err = store.VerifyOTP(ctx, session, code.OTP)
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid when not found, got %v", err)
	}
}

func TestKVOTPStore_Verify_Expired(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), 0)
	ctx := context.Background()

	session := "session-123"

	// Set with a negative duration to simulate expiration
	code, err := store.CreateOTP(ctx, session, "", -1*time.Minute)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = store.VerifyOTP(ctx, session, code.OTP)
	if err != otp.ErrOTPExpired {
		t.Fatalf("expected ErrOTPExpired, got %v", err)
	}
}

func TestKVOTPStore_Revoke_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), 0)
	ctx := context.Background()

	session := "session-123"
	code, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = store.RevokeOTP(ctx, session)
	if err != nil {
		t.Fatalf("expected no error on revoke, got %v", err)
	}

	err = store.VerifyOTP(ctx, session, code.OTP)
	if err != otp.ErrOTPInvalid {
		t.Fatalf("expected ErrOTPInvalid after revocation, got %v", err)
	}
}

func TestKVOTPStore_SendCooldown_BlocksSecondCreate(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), time.Minute)
	ctx := context.Background()
	session := "session-123"

	_, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("first CreateOTP: %v", err)
	}

	_, err = store.CreateOTP(ctx, session, "", 5*time.Minute)
	if !errors.Is(err, otp.ErrOTPSendRateLimited) {
		t.Fatalf("expected ErrOTPSendRateLimited, got %v", err)
	}

	if err := store.RevokeOTP(ctx, session); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	_, err = store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateOTP after revoke: %v", err)
	}
}

func TestKVOTPStore_SendCooldown_AllowsAfterExpiry(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), time.Hour)
	ctx := context.Background()
	session := "session-123"

	_, err := store.CreateOTP(ctx, session, "", -time.Minute)
	if err != nil {
		t.Fatalf("first CreateOTP: %v", err)
	}

	_, err = store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateOTP after expired challenge should succeed, got %v", err)
	}
}

func TestKVOTPStore_SendCooldown_BlocksDifferentTransitionSameEmail(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), time.Minute)
	ctx := context.Background()
	email := "user@example.com"

	_, err := store.CreateOTP(ctx, "transition-a", email, 5*time.Minute)
	if err != nil {
		t.Fatalf("first CreateOTP: %v", err)
	}

	_, err = store.CreateOTP(ctx, "transition-b", email, 5*time.Minute)
	if !errors.Is(err, otp.ErrOTPSendRateLimited) {
		t.Fatalf("expected ErrOTPSendRateLimited for second transition same email, got %v", err)
	}
}

func TestKVOTPStore_SendCooldown_NormalizesEmailForCooldown(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), time.Minute)
	ctx := context.Background()

	_, err := store.CreateOTP(ctx, "transition-a", " User@Example.COM ", 5*time.Minute)
	if err != nil {
		t.Fatalf("first CreateOTP: %v", err)
	}

	_, err = store.CreateOTP(ctx, "transition-b", "user@example.com", 5*time.Minute)
	if !errors.Is(err, otp.ErrOTPSendRateLimited) {
		t.Fatalf("expected ErrOTPSendRateLimited after normalization, got %v", err)
	}
}

func TestKVOTPStore_CreateOTP_RevokesPreviousCodeOnResend(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), 0)
	ctx := context.Background()
	session := "session-123"

	first, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("first CreateOTP: %v", err)
	}

	second, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("second CreateOTP: %v", err)
	}
	if second.OTP == first.OTP {
		t.Fatal("expected a new OTP code after resend")
	}

	if err := store.VerifyOTP(ctx, session, first.OTP); err != otp.ErrOTPInvalid {
		t.Fatalf("old OTP should be revoked, got %v", err)
	}

	if err := store.VerifyOTP(ctx, session, second.OTP); err != nil {
		t.Fatalf("new OTP should verify, got %v", err)
	}
}

func TestKVOTPStore_CreateOTP_RateLimitedDoesNotRevoke(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), time.Minute)
	ctx := context.Background()
	session := "session-123"

	code, err := store.CreateOTP(ctx, session, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("first CreateOTP: %v", err)
	}

	_, err = store.CreateOTP(ctx, session, "", 5*time.Minute)
	if !errors.Is(err, otp.ErrOTPSendRateLimited) {
		t.Fatalf("expected ErrOTPSendRateLimited, got %v", err)
	}

	if err := store.VerifyOTP(ctx, session, code.OTP); err != nil {
		t.Fatalf("original OTP should still verify after rate-limited resend, got %v", err)
	}
}

func TestKVOTPStore_SendCooldown_RecipientEmptySkipsCrossTransitionLimit(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVOTPStore(mockKV, []byte("super-secret"), time.Minute)
	ctx := context.Background()

	_, err := store.CreateOTP(ctx, "transition-a", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("first CreateOTP: %v", err)
	}

	_, err = store.CreateOTP(ctx, "transition-b", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("second transition with empty recipient should succeed, got %v", err)
	}

	_, err = store.CreateOTP(ctx, "transition-b", "", 5*time.Minute)
	if !errors.Is(err, otp.ErrOTPSendRateLimited) {
		t.Fatalf("expected ErrOTPSendRateLimited for same transition twice, got %v", err)
	}
}
