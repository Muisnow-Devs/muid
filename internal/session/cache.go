package session

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MaxSessionCacheTTL is the upper bound for Redis cache entry lifetime.
const MaxSessionCacheTTL = time.Hour

// CachedSession is a validated user session snapshot stored in Redis.
type CachedSession struct {
	SessionID     uuid.UUID
	UserID        uuid.UUID
	ValidatorHash [32]byte

	Email string

	IssuedAt       time.Time
	ExpiresAt      time.Time
	AbsoluteExpiry time.Time
}

// SessionCache stores resolved sessions with TTL bounded by session expiry.
// Methods take the full wire session token; the implementation derives the storage
// key from the token and validates the validator before returning a snapshot.
//
// Get returns [ErrSessionCacheRejected] when an entry exists for the token's selector
// but the wire validator does not match the cached hash (callers resolving sessions
// must not treat this as a cache miss that falls through to the database).
type SessionCache interface {
	Get(
		ctx context.Context,
		selector string,
	) (CachedSession, bool, error) // returns (session, found, error)
	Set(ctx context.Context, selector string, sess CachedSession) error
	Delete(ctx context.Context, selector string) error
	DeleteByID(ctx context.Context, id string) error
}
