package otp

import (
	"errors"
	"fmt"
)

var (
	ErrOTPAuthFailed = errors.New("otp: authentication failed")

	ErrOTPNotFound     = fmt.Errorf("%w: OTP not found", ErrOTPAuthFailed)
	ErrOTPInvalid      = fmt.Errorf("%w: invalid OTP", ErrOTPAuthFailed)
	ErrOTPExpired      = fmt.Errorf("%w: OTP has expired", ErrOTPAuthFailed)
	ErrTooManyAttempts = fmt.Errorf("%w: too many OTP verification attempts", ErrOTPAuthFailed)

	// ErrOTPSendRateLimited is returned when CreateOTP is called again before the
	// configured send cooldown elapses for the same transition and/or recipient.
	ErrOTPSendRateLimited = errors.New("otp: OTP send rate limited")

	ErrOTPStoreClosed = errors.New("otp: OTP store is closed")
)
