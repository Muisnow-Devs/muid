package otp

import (
	"errors"
	"fmt"
)

var (
	ErrOTPAuthFailed = errors.New("otp: authentication failed")

	ErrOTPNotFound     = fmt.Errorf("%w: OTP not found or expired", ErrOTPAuthFailed)
	ErrOTPInvalid      = fmt.Errorf("%w: invalid OTP", ErrOTPAuthFailed)
	ErrOTPExpired      = fmt.Errorf("%w: OTP has expired", ErrOTPAuthFailed)
	ErrTooManyAttempts = fmt.Errorf("%w: too many OTP verification attempts", ErrOTPAuthFailed)

	ErrOTPStoreClosed = errors.New("otp: OTP store is closed")
)
