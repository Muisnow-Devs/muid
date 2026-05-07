package mailer

import "errors"

var (
	ErrInvalidEmailAddress = errors.New("mailer: invalid email address")
	ErrEmptyEmailContent   = errors.New("mailer: email content cannot be empty")
	ErrEmailSendFailed     = errors.New("mailer: failed to send email")
	ErrMailerClosed        = errors.New("mailer: mailer is closed")
)
