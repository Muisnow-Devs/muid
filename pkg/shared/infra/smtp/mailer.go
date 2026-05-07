package mailer

import (
	"context"

	"github.com/wneessen/go-mail"
	"sanzi.io/muid/pkg/shared/mailer"
)

type MailerConfig struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
	SSL      bool
}

type SMTPMailer struct {
	client *mail.Client

	config MailerConfig
}

func NewSMTPMailer(smtpConfig MailerConfig) (mailer.Mailer, error) {
	options := []mail.Option{
		mail.WithPort(smtpConfig.Port),
		mail.WithUsername(smtpConfig.Username),
		mail.WithPassword(smtpConfig.Password),
	}

	if smtpConfig.SSL {
		options = append(options, mail.WithSSL())
	}

	client, err := mail.NewClient(smtpConfig.Host, options...)
	if err != nil {
		return nil, err
	}

	return &SMTPMailer{client: client, config: smtpConfig}, nil
}

func (s *SMTPMailer) Send(ctx context.Context, msg mailer.Message) error {
	if len(msg.To) == 0 {
		return mailer.ErrInvalidEmailAddress
	}

	if msg.TextBody == "" && msg.HTMLBody == "" {
		return mailer.ErrEmptyEmailContent
	}

	email := mail.NewMsg()
	email.From(s.config.From)
	email.To(msg.To...)
	email.Subject(msg.Subject)

	if msg.TextBody != "" {
		email.SetBodyString(mail.TypeTextPlain, msg.TextBody)
	}

	if msg.HTMLBody != "" {
		email.SetBodyString(mail.TypeTextHTML, msg.HTMLBody)
	}

	return s.client.Send(email)
}

func (s *SMTPMailer) Close() error {
	return s.client.Close()
}
