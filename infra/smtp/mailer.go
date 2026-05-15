package smtp

import (
	"context"

	"github.com/wneessen/go-mail"
	sharedmailer "sanzi.io/muid/pkg/shared/mailer"
)

// SMTPMailer is the concrete go-mail SMTP client.
type SMTPMailer struct {
	client *mail.Client
	config MailerConfig
}

// NewSMTPMailer builds an SMTP [Mailer] using go-mail.
func NewSMTPMailer(smtpConfig MailerConfig) (Mailer, error) {
	options := []mail.Option{
		mail.WithPort(smtpConfig.Port),
		mail.WithUsername(smtpConfig.Username),
		mail.WithPassword(smtpConfig.Password),

		mail.WithTLSPolicy(mail.TLSMandatory),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
	}

	if smtpConfig.Port == 465 {
		options = append(options, mail.WithSSL())
	}

	client, err := mail.NewClient(smtpConfig.Host, options...)
	if err != nil {
		return nil, err
	}

	return &SMTPMailer{client: client, config: smtpConfig}, nil
}

func (s *SMTPMailer) Send(ctx context.Context, msg sharedmailer.Message) error {
	if len(msg.To) == 0 {
		return sharedmailer.ErrInvalidEmailAddress
	}

	if msg.TextBody == "" && msg.HTMLBody == "" {
		return sharedmailer.ErrEmptyEmailContent
	}

	email := mail.NewMsg()
	email.From(s.config.From)
	email.To(msg.To...)
	email.Subject(msg.Subject)

	if msg.TextBody != "" {
		email.SetBodyString(mail.TypeTextPlain, msg.TextBody)
	}

	if msg.HTMLBody != "" {
		email.AddAlternativeString(mail.TypeTextHTML, msg.HTMLBody)
	}

	return s.client.DialAndSend(email)
}

func (s *SMTPMailer) Close() error {
	return s.client.Close()
}
