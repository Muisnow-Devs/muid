package handlers

import (
	"context"
	"errors"

	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// RegisterTopicHandlers subscribes each handler on its topic. Non-nil errors from
// Handle are logged by the [pubsub.PubSub] implementation (e.g. NATS) with the topic name.
func RegisterTopicHandlers(
	ctx context.Context,
	ps pubsub.PubSub,
	deps MailerDeps,
	hs ...TopicHandler,
) error {
	for _, h := range hs {
		topic := h.Topic()

		err := ps.Subscribe(
			ctx,
			topic,
			h.SubscribeOptions(),
			func(ctx context.Context, message []byte) error {
				return handleEvent(ctx, message, deps, h)
			},
		)

		if err != nil {
			return &SubscribeTopicError{Topic: topic, Err: err}
		}
	}
	return nil
}

func handleEvent(ctx context.Context, message []byte, deps MailerDeps, handler TopicHandler) error {
	result, err := handler.Handle(ctx, deps.Templates, message)
	if err != nil {
		return err
	}

	err = deps.Mail.Send(ctx, result)
	if errors.Is(err, mailer.ErrInvalidEmailAddress) ||
		errors.Is(err, mailer.ErrEmptyEmailContent) {
		return err
	}

	if err != nil {
		return errors.Join(mailer.ErrEmailSendFailed, err)
	}

	return nil
}
