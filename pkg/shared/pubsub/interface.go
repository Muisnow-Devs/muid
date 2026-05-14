package pubsub

import (
	"context"

	"sanzi.io/muid/pkg/shared/topics"
)

// SubscribeOptions configures subscription behavior. The zero value is valid.
type SubscribeOptions struct {
	// QueueGroup, if non-empty, uses a queue subscription so multiple workers share delivery.
	QueueGroup string
}

type PubSub interface {
	Publish(topic topics.Topic, message []byte) error
	Subscribe(topic topics.Topic, opts SubscribeOptions, handler func(ctx context.Context, message []byte) error) error
}
