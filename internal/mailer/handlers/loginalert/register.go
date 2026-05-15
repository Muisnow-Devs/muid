package loginalert

import (
	"context"
	"time"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/mailer/handlers"
	"sanzi.io/muid/internal/templates"
	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// Handler subscribes to the login-alert topic and delivers email via SMTP.
type Handler struct{}

func (Handler) Topic() topics.Topic                       { return topics.TopicSendLoginAlert }
func (Handler) SubscribeOptions() pubsub.SubscribeOptions { return pubsub.SubscribeOptions{} }

func (Handler) Handle(
	ctx context.Context,
	templates templates.MailRenderer,
	payload []byte,
) (mailer.Message, error) {
	var ev mailpb.SendLoginAlertEmailEvent
	err := handlers.UnmarshalMailEventPayload(payload, &ev)
	if err != nil {
		return mailer.Message{}, err
	}

	email := ev.GetEmail()
	if email == "" {
		return mailer.Message{}, mailer.ErrInvalidEmailAddress
	}

	when := time.Now().UTC().Format(time.RFC1123Z)
	if ts := ev.GetOccurredAt(); ts != nil {
		when = ts.AsTime().UTC().Format(time.RFC1123Z)
	}

	locale := ev.GetLocale()
	rendered, err := templates.Render(ctx, locale, "login_alert", handlers.TopicLoginAlert{
		Device:            ev.GetDevice(),
		Location:          ev.GetLocation(),
		IPAddress:         ev.GetIpAddress(),
		Time:              when,
		SecureAccountLink: ev.GetSecureLink(),
	})
	if err != nil {
		return mailer.Message{}, err
	}

	return mailer.Message{
		To:       []string{email},
		Subject:  rendered.Subject,
		TextBody: rendered.Text,
		HTMLBody: rendered.HTML,
	}, nil
}
