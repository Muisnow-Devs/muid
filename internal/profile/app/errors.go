package app

import "errors"

// ErrMalformedProfileChangePayload indicates the NATS payload could not be
// unmarshalled into the profile-change Protobuf event type.
var ErrMalformedProfileChangePayload = errors.New("profile app: malformed profile change payload")
