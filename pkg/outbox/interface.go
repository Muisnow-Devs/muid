// Package outbox relays committed events to a publisher with lease-aware retries.
package outbox

import (
	"context"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// Record is an event claimed from an outbox store.
type Record struct {
	ID           uuid.UUID
	Subject      topics.Topic
	Payload      []byte
	AttemptCount int
	CreatedAt    time.Time
	LeaseID      uuid.UUID
}

// Store provides lease-protected access to pending outbox records.
type Store interface {
	Claim(ctx context.Context, now time.Time, leaseDuration time.Duration) (Record, bool, error)
	MarkPublished(ctx context.Context, eventID, leaseID uuid.UUID, publishedAt time.Time) error
	Reschedule(
		ctx context.Context,
		eventID, leaseID uuid.UUID,
		nextAttemptAt time.Time,
		lastError string,
	) error
}

// Publisher publishes an outbox event with delivery options.
type Publisher interface {
	PublishWithContext(ctx context.Context, topic topics.Topic, message []byte, opts pubsub.PublishOptions) error
}

// Config controls relay polling, leases, and retry timing. Zero values use defaults.
type Config struct {
	PollInterval   time.Duration
	LeaseDuration  time.Duration
	PublishTimeout time.Duration
	RetryDelay     time.Duration
	RetryCap       time.Duration
	MaxPerPoll     int
}
