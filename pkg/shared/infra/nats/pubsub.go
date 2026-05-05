package nats

import (
	"github.com/nats-io/nats.go"
	"sanzi.io/muid/pkg/shared/pubsub"
)

type NATSPubSub struct {
	conn *nats.Conn
}

func NewNATSPubSub(natsURL string) (pubsub.PubSub, error) {
	client, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}

	return &NATSPubSub{conn: client}, nil
}

func (n *NATSPubSub) Publish(topic string, message []byte) error {
	return n.conn.Publish(topic, message)
}

func (n *NATSPubSub) Subscribe(topic string, handler func(message []byte)) error {
	_, err := n.conn.Subscribe(topic, func(msg *nats.Msg) {
		handler(msg.Data)
	})

	return err
}

func (n *NATSPubSub) Close() error {
	n.conn.Close()
	return nil
}
