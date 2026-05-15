// Package smtp provides an SMTP-backed [Mailer] implementation.
package smtp

import sharedmailer "sanzi.io/muid/pkg/shared/mailer"

// Mailer is the outbound mail contract implemented by [NewSMTPMailer].
type Mailer = sharedmailer.Mailer

// Message is an email payload (see [sharedmailer.Message]).
type Message = sharedmailer.Message

// MailerConfig holds SMTP connection settings.
type MailerConfig struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
}
