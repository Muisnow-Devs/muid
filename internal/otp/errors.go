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

	ErrOTPStoreClosed = errors.New("otp: OTP store is closed")
)
