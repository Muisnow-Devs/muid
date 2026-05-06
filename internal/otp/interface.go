package otp

import (
	"context"
	"time"
)

type OTPStore interface {
	SetOTP(ctx context.Context, key, otp string, ttl time.Duration) error
	VerifyOTP(ctx context.Context, key, otp string) (bool, error)
	RevokeOTP(ctx context.Context, key string) error
}
