package app

import (
	"errors"
	"io"

	"sanzi.io/muid/infra/nats"
	smtpimpl "sanzi.io/muid/infra/smtp"
	"sanzi.io/muid/internal/templates"
	"sanzi.io/muid/pkg/errutil"
	sharedmailer "sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
)

type InfraDependencies struct {
	GlobalConfig Config

	PubSub    pubsub.PubSub
	Mail      sharedmailer.Mailer
	Templates templates.MailRenderer
}

func (d *InfraDependencies) Close() error {
	var errs []error
	if d.PubSub != nil {
		if c, ok := d.PubSub.(io.Closer); ok {
			err := c.Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	if d.Mail != nil {
		if c, ok := d.Mail.(interface{ Close() error }); ok {
			err := c.Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func NewInfra(cfg Config) (*InfraDependencies, error) {
	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		return nil, err
	}

	mailClient, err := smtpimpl.NewSMTPMailer(smtpimpl.MailerConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		From:     cfg.SMTPFrom,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
	})
	if err != nil {
		errutil.CloseIf(pubSub)
		return nil, err
	}

	tmpl := templates.NewTemplateLoader(
		templates.HTMLTemplatesFS,
		templates.TextTemplatesFS,
		templates.LocaleTemplateFS,
	)

	return &InfraDependencies{
		GlobalConfig: cfg,
		PubSub:       pubSub,
		Mail:         mailClient,
		Templates:    tmpl,
	}, nil
}
