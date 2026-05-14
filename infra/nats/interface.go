// Package nats provides a NATS-backed [PubSub] implementation.
package nats

import "sanzi.io/muid/pkg/shared/pubsub"

// PubSub is the publish/subscribe contract implemented by [NewNATSPubSub].
type PubSub = pubsub.PubSub
