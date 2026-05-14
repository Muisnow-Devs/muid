package app

import (
	"fmt"

	"sanzi.io/muid/internal/mailer/handlers"
	"sanzi.io/muid/internal/mailer/handlers/loginalert"
	"sanzi.io/muid/internal/mailer/handlers/otp"
)

// RegisterSubscribers wires pub/sub topics to mail handlers.
func RegisterSubscribers(infra *InfraDependencies) error {
	if err := handlers.RegisterTopicHandlers(infra.PubSub, handlers.MailerDeps{
		Mail:      infra.Mail,
		Templates: infra.Templates,
	},
		otp.Handler{},
		loginalert.Handler{},
	); err != nil {
		return fmt.Errorf("topic handlers: %w", err)
	}
	return nil
}
