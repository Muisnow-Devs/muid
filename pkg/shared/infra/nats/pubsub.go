package nats

import (
	"github.com/nats-io/nats.go"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
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

func (n *NATSPubSub) Publish(topic topics.Topic, message []byte) error {
	return n.conn.Publish(string(topic), message)
}

func (n *NATSPubSub) Subscribe(topic topics.Topic, handler func(message []byte)) error {
	_, err := n.conn.Subscribe(string(topic), func(msg *nats.Msg) {
		handler(msg.Data)
	})

	return err
}

func (n *NATSPubSub) Close() error {
	n.conn.Close()
	return nil
}
