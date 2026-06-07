package kv

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/kv"
)

type sessionCacheRecord struct {
	SessionID      string   `json:"session_id"`
	UserID         string   `json:"user_id"`
	Email          string   `json:"email,omitempty"`
	ExpiresAt      int64    `json:"expires_at"`
	IssuedAt       int64    `json:"issued_at"`
	AbsoluteExpiry int64    `json:"absolute_expiry,omitempty"`
	ValidatorHash  [32]byte `json:"validator_hash,omitempty"`
}

// KVSessionCache stores resolved session snapshots in a KV backend.
type KVSessionCache struct {
	client kv.KVStore
}

// NewKVSessionCache returns a KV-backed session cache.
func NewKVSessionCache(client kv.KVStore) session.SessionCache {
	return &KVSessionCache{client: client}
}

func (c *KVSessionCache) selectorCacheKey(selectorB64 string) string {
	return "muid:auth:session:sel:" + selectorB64
}

func (c *KVSessionCache) idCacheKey(id string) string {
	return "muid:auth:session:id:" + id
}

func (c *KVSessionCache) Get(
	ctx context.Context,
	selector string,
) (session.CachedSession, bool, error) {
	idBytes, err := c.client.Get(ctx, c.selectorCacheKey(selector))
	if errors.Is(err, kv.ErrKeyNotFound) { // cache miss
		return session.CachedSession{}, false, nil
	}
	if err != nil {
		return session.CachedSession{}, false, err
	}

	idStr := string(idBytes)
	data, err := c.client.Get(ctx, c.idCacheKey(idStr))
	if errors.Is(err, kv.ErrKeyNotFound) { // stale reference cleanup
		_ = c.client.Delete(ctx, c.selectorCacheKey(selector))
		return session.CachedSession{}, false, nil
	}
	if err != nil {
		return session.CachedSession{}, false, err
	}

	var rec sessionCacheRecord
	err = json.Unmarshal(data, &rec)
	if err != nil {
		return session.CachedSession{}, false, err
	}

	sid, err := uuid.Parse(rec.SessionID)
	if err != nil {
		return session.CachedSession{}, false, err
	}

	uid, err := uuid.Parse(rec.UserID)
	if err != nil {
		return session.CachedSession{}, false, err
	}

	return session.CachedSession{
		SessionID:      sid,
		UserID:         uid,
		Email:          rec.Email,
		ExpiresAt:      time.Unix(rec.ExpiresAt, 0),
		IssuedAt:       time.Unix(rec.IssuedAt, 0),
		AbsoluteExpiry: time.Unix(rec.AbsoluteExpiry, 0),
		ValidatorHash:  rec.ValidatorHash,
	}, true, nil
}

func sessionCacheTTL(expiresAt time.Time) time.Duration {
	ttl := time.Until(expiresAt)
	return min(ttl, session.MaxSessionCacheTTL)
}

// Set stores a snapshot keyed by the token's selector. The snapshot validator hash must
// match the wire token's validator secret.
func (c *KVSessionCache) Set(
	ctx context.Context,
	selector string,
	sess session.CachedSession,
) error {
	ttl := sessionCacheTTL(sess.ExpiresAt)
	if ttl <= 0 {
		return session.ErrSessionExpired
	}

	rec := sessionCacheRecord{
		SessionID:      sess.SessionID.String(),
		UserID:         sess.UserID.String(),
		Email:          sess.Email,
		ExpiresAt:      sess.ExpiresAt.Unix(),
		IssuedAt:       sess.IssuedAt.Unix(),
		AbsoluteExpiry: sess.AbsoluteExpiry.Unix(),
		ValidatorHash:  sess.ValidatorHash,
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	id := sess.SessionID.String()
	// Store the session data under the ID key
	err = c.client.Set(ctx, c.idCacheKey(id), data, ttl)
	if err != nil {
		return err
	}

	// Store the selector -> ID reference
	return c.client.Set(ctx, c.selectorCacheKey(selector), []byte(id), ttl)
}

func (c *KVSessionCache) Delete(ctx context.Context, selector string) error {
	idBytes, err := c.client.Get(ctx, c.selectorCacheKey(selector))
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	idStr := string(idBytes)
	_ = c.client.Delete(ctx, c.idCacheKey(idStr))
	err = c.client.Delete(ctx, c.selectorCacheKey(selector))
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}
	return err
}

func (c *KVSessionCache) DeleteByID(ctx context.Context, id string) error {
	err := c.client.Delete(ctx, c.idCacheKey(id))
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}
	return err
}
