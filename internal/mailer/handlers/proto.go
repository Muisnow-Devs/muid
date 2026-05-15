package handlers

import (
	"errors"

	"google.golang.org/protobuf/proto"
)

func UnmarshalMailEventPayload[T proto.Message](payload []byte, ev T) error {
	err := proto.Unmarshal(payload, ev)
	if err != nil {
		return errors.Join(ErrMalformedMailEventPayload, err)
	}

	return nil
}
