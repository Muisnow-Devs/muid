package postgresoutbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"sanzi.io/muid/pkg/outbox"
	"sanzi.io/muid/pkg/shared/topics"
)

const maxLastErrorLength = 2048

// Store provides PostgreSQL-backed lease-protected access to outbox records.
type Store struct {
	db *sql.DB
}

var _ outbox.Store = (*Store)(nil)

// NewStore creates a Store using db.
func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalidConfig
	}

	return &Store{db: db}, nil
}

// Claim atomically leases the next due unpublished event, if one is available.
func (s *Store) Claim(ctx context.Context, now time.Time, leaseDuration time.Duration) (outbox.Record, bool, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || leaseDuration <= 0 {
		return outbox.Record{}, false, ErrInvalidConfig
	}

	leaseID := uuid.New()
	leaseUntil := now.Add(leaseDuration)
	row := s.db.QueryRowContext(ctx, `
WITH candidate AS (
    SELECT id
    FROM outbox_events
    WHERE published_at IS NULL
      AND next_attempt_at <= $1
      AND (lease_until IS NULL OR lease_until <= $1)
    ORDER BY next_attempt_at, created_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE outbox_events AS events
SET lease_id = $2,
    lease_until = $3,
    attempt_count = events.attempt_count + 1
FROM candidate
WHERE events.id = candidate.id
RETURNING events.id, events.subject, events.payload, events.attempt_count, events.created_at, events.lease_id`, now, leaseID, leaseUntil)

	var record outbox.Record
	err := row.Scan(
		&record.ID,
		&record.Subject,
		&record.Payload,
		&record.AttemptCount,
		&record.CreatedAt,
		&record.LeaseID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return outbox.Record{}, false, nil
	}
	if err != nil {
		return outbox.Record{}, false, fmt.Errorf("claiming outbox event: %w", err)
	}
	if !validRecord(record) {
		return outbox.Record{}, false, ErrInvalidConfig
	}

	return record, true, nil
}

// MarkPublished marks an event as published only while its lease is still owned.
func (s *Store) MarkPublished(
	ctx context.Context,
	eventID, leaseID uuid.UUID,
	publishedAt time.Time,
) error {
	if s == nil || s.db == nil || ctx == nil || eventID == uuid.Nil || leaseID == uuid.Nil || publishedAt.IsZero() {
		return ErrInvalidConfig
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE outbox_events
SET published_at = $3,
    lease_id = NULL,
    lease_until = NULL,
    last_error = NULL
WHERE id = $1
  AND lease_id = $2
  AND published_at IS NULL`, eventID, leaseID, publishedAt)
	if err != nil {
		return fmt.Errorf("marking outbox event published: %w", err)
	}

	return requireLease(result)
}

// Reschedule records a failed attempt and releases the current lease.
func (s *Store) Reschedule(
	ctx context.Context,
	eventID, leaseID uuid.UUID,
	nextAttemptAt time.Time,
	lastError string,
) error {
	if s == nil || s.db == nil || ctx == nil || eventID == uuid.Nil || leaseID == uuid.Nil || nextAttemptAt.IsZero() {
		return ErrInvalidConfig
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE outbox_events
SET next_attempt_at = $3,
    last_error = $4,
    lease_id = NULL,
    lease_until = NULL
WHERE id = $1
  AND lease_id = $2
  AND published_at IS NULL`, eventID, leaseID, nextAttemptAt, truncateLastError(lastError))
	if err != nil {
		return fmt.Errorf("rescheduling outbox event: %w", err)
	}

	return requireLease(result)
}

func requireLease(result sql.Result) error {
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading outbox update result: %w", err)
	}
	if rowsAffected != 1 {
		return ErrLeaseLost
	}

	return nil
}

func validRecord(record outbox.Record) bool {
	return record.ID != uuid.Nil &&
		record.Subject != topics.Topic("") &&
		len(record.Payload) > 0 &&
		record.AttemptCount > 0 &&
		!record.CreatedAt.IsZero() &&
		record.LeaseID != uuid.Nil
}

func truncateLastError(message string) string {
	if len(message) <= maxLastErrorLength {
		return message
	}

	limit := maxLastErrorLength
	for limit > 0 && !utf8.RuneStart(message[limit]) {
		limit--
	}
	return message[:limit]
}
