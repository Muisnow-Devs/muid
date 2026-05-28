package accountunlinked

import (
	"context"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/mailer/handlers"
	"sanzi.io/muid/internal/templates"
	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// Handler subscribes to account-unlinked notifications.
type Handler struct{}

func (Handler) Topic() topics.Topic { return topics.TopicAccountUnlinked }
func (Handler) SubscribeOptions() pubsub.SubscribeOptions {
	return handlers.ReliableMailSubscribeOptions(topics.TopicAccountUnlinked)
}

func (Handler) Handle(
	ctx context.Context,
	tmpl templates.MailRenderer,
	payload []byte,
) (mailer.Message, error) {
	var ev mailpb.SendAccountUnlinkedEmailEvent
	if err := handlers.UnmarshalMailEventPayload(payload, &ev); err != nil {
		return mailer.Message{}, err
	}

	email := ev.GetEmail()
	if email == "" {
		return mailer.Message{}, mailer.ErrInvalidEmailAddress
	}

	when := handlers.FormatEventTime(ev.GetOccurredAt(), ev.GetTimezone())
	rendered, err := tmpl.Render(
		ctx,
		ev.GetLocale(),
		"account_unlinked",
		handlers.TopicAccountUnlinked{
			Provider: ev.GetProvider(),
			Time:     when,
		},
	)
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
