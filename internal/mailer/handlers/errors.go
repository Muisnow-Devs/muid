package handlers

import (
	"errors"

	"sanzi.io/muid/pkg/shared/topics"
)

// ErrMalformedMailEventPayload indicates the NATS payload could not be unmarshalled
// into the expected Protobuf message for this topic.
var ErrMalformedMailEventPayload = errors.New("mailer handlers: malformed mail event payload")

// SubscribeTopicError records a failure subscribing a mail handler to its NATS topic.
type SubscribeTopicError struct {
	Topic topics.Topic
	Err   error
}

func (e *SubscribeTopicError) Error() string {
	return "mailer handlers: subscribe " + string(e.Topic)
}

func (e *SubscribeTopicError) Unwrap() error { return e.Err }
