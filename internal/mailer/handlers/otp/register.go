package otp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/mailer/handlers"
	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// Handler subscribes to the send-OTP topic and delivers email via SMTP.
type Handler struct{}

func (Handler) Topic() topics.Topic                       { return topics.TopicSendOTP }
func (Handler) SubscribeOptions() pubsub.SubscribeOptions { return pubsub.SubscribeOptions{} }
func (Handler) Handle(ctx context.Context, deps handlers.MailerDeps, payload []byte) error {
	var ev mailpb.SendOTPEmailEvent
	if err := proto.Unmarshal(payload, &ev); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return sendOTPEmail(ctx, deps, &ev)
}

func sendOTPEmail(ctx context.Context, deps handlers.MailerDeps, ev *mailpb.SendOTPEmailEvent) error {
	if ev.GetEmail() == "" || ev.GetCode() == "" {
		return mailer.ErrInvalidEmailAddress
	}
	product := ev.GetProductName()
	if product == "" {
		product = "Muid"
	}
	expires := time.Unix(ev.GetExpiresAt(), 0).UTC().Format(time.RFC1123Z)
	locale := ev.GetLocale()

	rendered, err := deps.Templates.Render(ctx, locale, "otp", struct {
		OTP         string
		ExpiryTime  string
		ProductName string
	}{
		OTP:         ev.GetCode(),
		ExpiryTime:  expires,
		ProductName: product,
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
	return deps.Mail.Send(ctx, msg)
}
