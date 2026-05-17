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
	ExpiresAt     time.Time
	ValidatorHash [32]byte
}

// SessionCache stores resolved sessions with TTL bounded by session expiry.
type SessionCache interface {
	Get(ctx context.Context, selectorKey string) (CachedSession, error)
	Set(ctx context.Context, selectorKey string, sess CachedSession) error
	Delete(ctx context.Context, selectorKey string) error
}
