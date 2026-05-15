package otp

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

// Handler subscribes to the send-OTP topic and delivers email via SMTP.
type Handler struct{}

func (Handler) Topic() topics.Topic                       { return topics.TopicSendOTP }
func (Handler) SubscribeOptions() pubsub.SubscribeOptions { return pubsub.SubscribeOptions{} }

func (Handler) Handle(
	ctx context.Context,
	templates templates.MailRenderer,
	payload []byte,
) (mailer.Message, error) {
	var ev mailpb.SendOTPEmailEvent
	err := handlers.UnmarshalMailEventPayload(payload, &ev)
	if err != nil {
		return mailer.Message{}, err
	}

	email := ev.GetEmail()
	if email == "" || ev.GetCode() == "" {
		return mailer.Message{}, mailer.ErrInvalidEmailAddress
	}

	expires := time.Now().UTC().Format(time.RFC1123Z)
	if ts := ev.GetExpiresAt(); ts != nil {
		expires = ts.AsTime().UTC().Format(time.RFC1123Z)
	}
	locale := ev.GetLocale()

	rendered, err := templates.Render(ctx, locale, "otp", handlers.TopicOTP{
		OTP:        ev.GetCode(),
		ExpiryTime: expires,
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
