package account

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Status is the account lifecycle state.
type Status string

const (
	// StatusActive indicates an account may be used normally.
	StatusActive Status = "active"
	// StatusDisabled indicates an account has been disabled.
	StatusDisabled Status = "disabled"
	// StatusPendingDeletion indicates an account is scheduled for deletion.
	StatusPendingDeletion Status = "pending_deletion"
)

// Snapshot is the account state safe to return to an authenticated account owner.
type Snapshot struct {
	Status           Status
	PrimaryEmail     string
	CreatedAt        time.Time
	LinkedIdentities []LinkedIdentity
}

// LinkedIdentity identifies an active federated login linked to an account.
type LinkedIdentity struct {
	Provider string
	LinkedAt time.Time
}

// Reader reads an authenticated user's account state.
type Reader interface {
	GetMyAccount(context.Context, uuid.UUID) (Snapshot, error)
}
