package handlers

import (
	"context"

	"sanzi.io/muid/pkg/shared/pubsub"
)

// RegisterTopicHandlers subscribes each handler on its topic. Non-nil errors from
// Handle are logged by the [pubsub.PubSub] implementation (e.g. NATS) with the topic name.
func RegisterTopicHandlers(ctx context.Context, ps pubsub.PubSub, deps MailerDeps, hs ...TopicHandler) error {
	for _, h := range hs {
		topic := h.Topic()

		err := ps.Subscribe(
			ctx,
			topic,
			h.SubscribeOptions(),
			func(ctx context.Context, message []byte) error {
				return h.Handle(ctx, deps, message)
			},
		)

		if err != nil {
			return &SubscribeTopicError{Topic: topic, Err: err}
		}
	}
	return nil
}
