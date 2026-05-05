package otp

import "errors"

var (
	ErrOTPNotFound       = errors.New("otp: OTP not found or expired")
	ErrOTPInvalid        = errors.New("otp: invalid OTP")
	ErrTooManyAttempts   = errors.New("otp: too many OTP verification attempts")
	ErrOTPMismatchLength = errors.New("otp: OTP length mismatch")
	ErrOTPStoreClosed    = errors.New("otp: OTP store is closed")
)
