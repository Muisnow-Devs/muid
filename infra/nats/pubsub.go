package nats

import (
	"context"

	natsio "github.com/nats-io/nats.go"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/traceid"
)

type NATSPubSub struct {
	conn *natsio.Conn
}

// NewNATSPubSub connects to NATS at natsURL and returns a [PubSub] client.
func NewNATSPubSub(natsURL string) (PubSub, error) {
	client, err := natsio.Connect(natsURL)
	if err != nil {
		return nil, err
	}

	return &NATSPubSub{conn: client}, nil
}

func (n *NATSPubSub) Publish(topic topics.Topic, message []byte) error {
	return n.conn.Publish(string(topic), message)
}

func (n *NATSPubSub) Subscribe(
	ctx context.Context,
	topic topics.Topic,
	opts pubsub.SubscribeOptions,
	handler func(ctx context.Context, message []byte) error,
) error {
	cb := func(msg *natsio.Msg) {
		workCtx, cancel := context.WithTimeout(ctx, pubsub.SubscribeTaskTimeout)
		defer cancel()

		ctx := traceid.With(context.Background(), shared.UUIDV7().String())

		if err := handler(workCtx, msg.Data); err != nil {
			traceid.LogUnexpected(ctx, "nats subscriber", err.Error(), "topic", string(topic))
		}
	}

	var err error
	if opts.QueueGroup != "" {
		_, err = n.conn.QueueSubscribe(string(topic), opts.QueueGroup, cb)
	} else {
		_, err = n.conn.Subscribe(string(topic), cb)
	}

	return err
}

func (n *NATSPubSub) Close() error {
	n.conn.Close()
	return nil
}
