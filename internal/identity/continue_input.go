package identity

import "github.com/google/uuid"

func ProvisionedUserID(input ContinueInput) (uuid.UUID, error) {
	if input.ContinueState != ContinueStateFinishRegister {
		return uuid.Nil, ErrInvalidInput
	}
	if input.FinishRegister == nil {
		return uuid.Nil, ErrInvalidInput
	}
	uid := input.FinishRegister.RegisteredUserID
	if uid == uuid.Nil {
		return uuid.Nil, ErrInvalidInput
	}
	if len(input.Payload) > 0 {
		return uuid.Nil, ErrInvalidInput
	}
	return uid, nil
}

func ValidateContinueChallenge(input ContinueInput) error {
	if input.ContinueState != ContinueStateChallenge {
		return ErrInvalidInput
	}
	if input.FinishRegister != nil {
		return ErrInvalidInput
	}
	return nil
}

func ValidateContinueResend(input ContinueInput) error {
	if input.ContinueState != ContinueStateResend {
		return ErrInvalidInput
	}
	if input.FinishRegister != nil {
		return ErrInvalidInput
	}
	if len(input.Payload) > 0 {
		return ErrInvalidInput
	}
	return nil
}
