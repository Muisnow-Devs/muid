package otp

import (
	"context"
	"time"
)

type OTPChallenge struct {
	OTP       string
	ExpiresAt time.Time
}

type OTPStore interface {
	CreateOTP(ctx context.Context, transitionId string, ttl time.Duration) (OTPChallenge, error)
	VerifyOTP(ctx context.Context, transitionId, otp string) error
	RevokeOTP(ctx context.Context, transitionId string) error
}
