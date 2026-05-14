package loginalert

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/mailer/handlers"
	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// Handler subscribes to the login-alert topic and delivers email via SMTP.
type Handler struct{}

func (Handler) Topic() topics.Topic                       { return topics.TopicSendLoginAlert }
func (Handler) SubscribeOptions() pubsub.SubscribeOptions { return pubsub.SubscribeOptions{} }
func (Handler) Handle(ctx context.Context, deps handlers.MailerDeps, payload []byte) error {
	var ev mailpb.SendLoginAlertEmailEvent
	if err := proto.Unmarshal(payload, &ev); err != nil {
		return errors.Join(handlers.ErrMalformedMailEventPayload, err)
	}
	return sendLoginAlertEmail(ctx, deps, &ev)
}

func sendLoginAlertEmail(
	ctx context.Context,
	deps handlers.MailerDeps,
	ev *mailpb.SendLoginAlertEmailEvent,
) error {
	if ev.GetEmail() == "" {
		return mailer.ErrInvalidEmailAddress
	}
	locale := ev.GetLocale()
	when := time.Now().UTC().Format(time.RFC1123Z)
	if ts := ev.GetOccurredAt(); ts != nil {
		when = ts.AsTime().UTC().Format(time.RFC1123Z)
	}

	rendered, err := deps.Templates.Render(ctx, locale, "login_alert", struct {
		Device            string
		Location          string
		IPAddress         string
		Time              string
		SecureAccountLink string
	}{
		Device:            ev.GetDevice(),
		Location:          ev.GetLocation(),
		IPAddress:         ev.GetIpAddress(),
		Time:              when,
		SecureAccountLink: "#",
	})
	if err != nil {
		return err
	}

	msg := mailer.Message{
		To:       []string{ev.GetEmail()},
		Subject:  rendered.Subject,
		TextBody: rendered.Text,
		HTMLBody: rendered.HTML,
	}
	if err := deps.Mail.Send(ctx, msg); err != nil {
		if errors.Is(err, mailer.ErrInvalidEmailAddress) ||
			errors.Is(err, mailer.ErrEmptyEmailContent) {
			return err
		}
		return errors.Join(mailer.ErrEmailSendFailed, err)
	}
	return nil
}
