package otp

import (
	"context"
	"time"
)

type OTPStore interface {
	CreateOTP(ctx context.Context, key string, ttl time.Duration) (string, error)
	VerifyOTP(ctx context.Context, key, otp string) (bool, error)
	RevokeOTP(ctx context.Context, key string) error
}
