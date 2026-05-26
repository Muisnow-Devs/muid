package handlers

import (
	"context"
	"strings"

	"sanzi.io/muid/internal/templates"
	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// MailerDeps bundles collaborators for mail-delivering topic handlers.
type MailerDeps struct {
	Mail      mailer.Mailer
	Templates templates.MailRenderer
}

// TopicHandler binds one pub/sub topic to mail handling: optional subscribe options,
// unmarshaling of the wire payload, and context-first processing with explicit errors.
type TopicHandler interface {
	Topic() topics.Topic
	SubscribeOptions() pubsub.SubscribeOptions
	Handle(
		ctx context.Context,
		templates templates.MailRenderer,
		payload []byte,
	) (mailer.Message, error)
}

func ReliableMailSubscribeOptions(topic topics.Topic) pubsub.SubscribeOptions {
	return pubsub.SubscribeOptions{
		QueueGroup:  "mailer",
		Reliable:    true,
		Durable:     "mailer_" + strings.ReplaceAll(string(topic), ".", "_"),
		RetryPolicy: pubsub.CriticalRetryPolicy(),
	}
}

type TopicOTP struct {
	OTP        string
	ExpiryTime string
}

type TopicEmailChanged struct {
	OldEmail string
	NewEmail string
	Time     string
}

type TopicPasskeyAdded struct {
	PasskeyName string
	Time        string
}

type TopicLoginAlert struct {
	Device    string
	Location  string
	IPAddress string
	Time      string

	SecureAccountLink string
}

type TopicAccountLinked struct {
	Provider string
	Time     string
}
