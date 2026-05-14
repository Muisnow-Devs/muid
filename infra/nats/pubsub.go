package nats

import (
	"context"
	"log"

	natsio "github.com/nats-io/nats.go"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
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

func (n *NATSPubSub) Subscribe(topic topics.Topic, opts pubsub.SubscribeOptions, handler func(ctx context.Context, message []byte) error) error {
	cb := func(msg *natsio.Msg) {
		ctx := context.Background()
		if err := handler(ctx, msg.Data); err != nil {
			log.Printf("%s: %v", topic, err)
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
