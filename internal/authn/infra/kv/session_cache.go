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
	SessionID     string `json:"session_id"`
	UserID        string `json:"user_id"`
	ExpiresAt     int64  `json:"expires_at"`
	ValidatorHash []byte `json:"validator_hash,omitempty"`
}

type KVSessionCache struct {
	client kv.KVStore
}

func NewKVSessionCache(client kv.KVStore) session.SessionCache {
	return &KVSessionCache{client: client}
}

func (c *KVSessionCache) cacheKey(selectorKey string) string {
	return "muid:auth:session:sel:" + selectorKey
}

func (c *KVSessionCache) Get(
	ctx context.Context,
	selectorKey string,
) (session.CachedSession, error) {
	data, err := c.client.Get(ctx, c.cacheKey(selectorKey))
	if err != nil {
		if errors.Is(err, kv.ErrKeyNotFound) {
			return session.CachedSession{}, session.ErrSessionNotFound
		}
		return session.CachedSession{}, err
	}
	var rec sessionCacheRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return session.CachedSession{}, err
	}
	sid, err := uuid.Parse(rec.SessionID)
	if err != nil {
		return session.CachedSession{}, err
	}
	uid, err := uuid.Parse(rec.UserID)
	if err != nil {
		return session.CachedSession{}, err
	}
	exp := time.Unix(rec.ExpiresAt, 0)
	if time.Now().After(exp) {
		_ = c.Delete(ctx, selectorKey)
		return session.CachedSession{}, session.ErrSessionExpired
	}
	var validatorHash [32]byte
	if len(rec.ValidatorHash) == len(validatorHash) {
		copy(validatorHash[:], rec.ValidatorHash)
	}

	return session.CachedSession{
		SessionID:     sid,
		UserID:        uid,
		ExpiresAt:     exp,
		ValidatorHash: validatorHash,
	}, nil
}

func sessionCacheTTL(expiresAt time.Time) time.Duration {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return 0
	}
	if ttl > session.MaxSessionCacheTTL {
		return session.MaxSessionCacheTTL
	}
	return ttl
}

func (c *KVSessionCache) Set(
	ctx context.Context,
	selectorKey string,
	sess session.CachedSession,
) error {
	ttl := sessionCacheTTL(sess.ExpiresAt)
	if ttl <= 0 {
		return session.ErrSessionExpired
	}
	rec := sessionCacheRecord{
		SessionID:     sess.SessionID.String(),
		UserID:        sess.UserID.String(),
		ExpiresAt:     sess.ExpiresAt.Unix(),
		ValidatorHash: sess.ValidatorHash[:],
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.cacheKey(selectorKey), data, ttl)
}

func (c *KVSessionCache) Delete(ctx context.Context, selectorKey string) error {
	err := c.client.Delete(ctx, c.cacheKey(selectorKey))
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}
	return err
}
