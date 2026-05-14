package handlers

import (
	"context"
	"fmt"

	"sanzi.io/muid/pkg/shared/pubsub"
)

// RegisterTopicHandlers subscribes each handler on its topic. Non-nil errors from
// Handle are logged by the [pubsub.PubSub] implementation (e.g. NATS) with the topic name.
func RegisterTopicHandlers(ps pubsub.PubSub, deps MailerDeps, hs ...TopicHandler) error {
	for _, h := range hs {
		h := h
		topic := h.Topic()
		if err := ps.Subscribe(topic, h.SubscribeOptions(), func(ctx context.Context, message []byte) error {
			return h.Handle(ctx, deps, message)
		}); err != nil {
			return fmt.Errorf("subscribe %s: %w", topic, err)
		}
	}
	return nil
}
