package pubsub

import "sanzi.io/muid/pkg/shared/topics"

type PubSub interface {
	Publish(topic topics.Topic, message []byte) error
	Subscribe(topic topics.Topic, handler func(message []byte)) error
}
