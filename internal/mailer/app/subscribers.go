package app

import (
	"context"

	"sanzi.io/muid/internal/mailer/handlers"
	"sanzi.io/muid/internal/mailer/handlers/emailchanged"
	"sanzi.io/muid/internal/mailer/handlers/loginalert"
	"sanzi.io/muid/internal/mailer/handlers/otp"
	"sanzi.io/muid/internal/mailer/handlers/passkeyadded"
)

// RegisterSubscribers wires pub/sub topics to mail handlers.
func RegisterSubscribers(ctx context.Context, infra *InfraDependencies) error {
	if err := handlers.RegisterTopicHandlers(ctx, infra.PubSub, handlers.MailerDeps{
		Mail:      infra.Mail,
		Templates: infra.Templates,
	},
		otp.Handler{},
		loginalert.Handler{},
		emailchanged.Handler{},
		passkeyadded.Handler{},
	); err != nil {
		return err
	}
	return nil
}
