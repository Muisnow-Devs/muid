package shared

import (
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
)

func UUIDV7() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}

func ULID() string {
	return ulid.Make().String()
}
