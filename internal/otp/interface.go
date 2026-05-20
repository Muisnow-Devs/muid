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
	// CreateOTP issues an OTP for transitionId. recipient is the delivery address (e.g. email),
	// used only for send cooldown; it is normalized in the store. Empty recipient skips per-recipient cooldown.
	CreateOTP(
		ctx context.Context,
		transitionId string,
		recipient string,
		ttl time.Duration,
	) (OTPChallenge, error)
	VerifyOTP(ctx context.Context, transitionId, otp string) error
	RevokeOTP(ctx context.Context, transitionId string) error
}
