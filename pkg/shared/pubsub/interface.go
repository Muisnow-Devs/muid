package pubsub

import (
	"context"
	"time"

	"sanzi.io/muid/pkg/shared/topics"
)

const (
	// SubscribeTaskTimeout is the maximum duration for a subscription handler to run before timing out.
	SubscribeTaskTimeout = 30 * time.Second
)

// SubscribeOptions configures subscription behavior. The zero value is valid.
type SubscribeOptions struct {
	// QueueGroup, if non-empty, uses a queue subscription so multiple workers share delivery.
	QueueGroup string
}

type PubSub interface {
	Publish(topic topics.Topic, message []byte) error
	Subscribe(
		ctx context.Context,
		topic topics.Topic,
		opts SubscribeOptions,
		handler func(ctx context.Context, message []byte) error,
	) error
}
