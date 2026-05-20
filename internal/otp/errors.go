package otp

import (
	"errors"
	"fmt"
)

var (
	ErrOTPAuthFailed = errors.New("otp: authentication failed")

	ErrOTPNotFound     = fmt.Errorf("otp: OTP not found: %w", ErrOTPAuthFailed)
	ErrOTPInvalid      = fmt.Errorf("otp: invalid OTP: %w", ErrOTPAuthFailed)
	ErrOTPExpired      = fmt.Errorf("otp: OTP has expired: %w", ErrOTPAuthFailed)
	ErrTooManyAttempts = fmt.Errorf("otp: too many OTP verification attempts: %w", ErrOTPAuthFailed)

	// ErrOTPSendRateLimited is returned when CreateOTP is called again before the
	// configured send cooldown elapses for the same transition and/or recipient.
	ErrOTPSendRateLimited = errors.New("otp: OTP send rate limited")

	ErrOTPStoreClosed = errors.New("otp: OTP store is closed")
)
