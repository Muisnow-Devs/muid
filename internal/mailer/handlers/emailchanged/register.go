package emailchanged

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

// Handler subscribes to email-changed notifications.
type Handler struct{}

func (Handler) Topic() topics.Topic                       { return topics.TopicEmailChanged }
func (Handler) SubscribeOptions() pubsub.SubscribeOptions { return pubsub.SubscribeOptions{} }

func (Handler) Handle(
	ctx context.Context,
	tmpl templates.MailRenderer,
	payload []byte,
) (mailer.Message, error) {
	var ev mailpb.SendEmailChangedEvent
	if err := handlers.UnmarshalMailEventPayload(payload, &ev); err != nil {
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
	rendered, err := tmpl.Render(ctx, ev.GetLocale(), "email_changed", handlers.TopicEmailChanged{
		OldEmail: ev.GetOldEmail(),
		NewEmail: ev.GetNewEmail(),
		Time:     when,
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
