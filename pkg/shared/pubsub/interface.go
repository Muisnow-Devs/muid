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
	// Reliable enables acked delivery with server-side redelivery when the backend supports it.
	Reliable bool
	// Durable names the durable subscription/consumer for reliable delivery.
	Durable string
	// RetryPolicy controls failed message redelivery. Empty fields use defaults.
	RetryPolicy RetryPolicy
}

// PublishOptions configures message publishing behavior. The zero value is valid.
type PublishOptions struct {
	// Reliable asks the backend to persist the message before acknowledging publish success.
	Reliable bool
	// RetryPolicy is encoded with the message so subscribers can apply publisher intent.
	RetryPolicy RetryPolicy
}

type PubSub interface {
	Publish(topic topics.Topic, message []byte) error
	PublishWithOptions(topic topics.Topic, message []byte, opts PublishOptions) error
	Subscribe(
		ctx context.Context,
		topic topics.Topic,
		opts SubscribeOptions,
		handler func(ctx context.Context, message []byte) error,
	) error
}
