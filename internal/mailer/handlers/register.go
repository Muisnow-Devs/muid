package handlers

import (
	"context"
	"errors"
	"log/slog"

	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
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
		return errors.Join(pubsub.ErrNonRetryable, err)
	}

	err = deps.Mail.Send(ctx, result)
	logMailSendAttempt(ctx, handler.Topic(), result, err)
	if errors.Is(err, mailer.ErrInvalidEmailAddress) ||
		errors.Is(err, mailer.ErrEmptyEmailContent) {
		return errors.Join(pubsub.ErrNonRetryable, err)
	}

	if err != nil {
		return errors.Join(mailer.ErrEmailSendFailed, err)
	}

	return nil
}

func logMailSendAttempt(ctx context.Context, topic topics.Topic, msg mailer.Message, err error) {
	attrs := []any{
		slog.String("topic", string(topic)),
		slog.Any("to", msg.To),
		slog.Int("recipient_count", len(msg.To)),
	}
	if err != nil {
		attrs = append(attrs,
			slog.String("result", "failure"),
			slog.Any("err", err),
		)
		log.Logger(ctx).Info("mail send attempt", attrs...)
		return
	}

	attrs = append(attrs, slog.String("result", "success"))
	log.Logger(ctx).Info("mail send attempt", attrs...)
}
