package kv

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	Email         string `json:"email,omitempty"`
	ExpiresAt     int64  `json:"expires_at"`
	IssuedAt      int64  `json:"issued_at"`
	ValidatorHash []byte `json:"validator_hash,omitempty"`
}

type KVSessionCache struct {
	client kv.KVStore
}

func NewKVSessionCache(client kv.KVStore) session.SessionCache {
	return &KVSessionCache{client: client}
}

func (c *KVSessionCache) selectorCacheKey(selectorB64 string) string {
	return "muid:auth:session:sel:" + selectorB64
}

// Get loads a cache entry for the token's selector and returns it only when the
// wire token's validator matches the stored hash.
func (c *KVSessionCache) Get(ctx context.Context, wireToken string) (session.CachedSession, error) {
	selectorB64, validatorB64, err := session.ParseWireSessionToken(wireToken)
	if err != nil {
		return session.CachedSession{}, err
	}
	secret, err := session.DecodeWireValidatorSecret(validatorB64)
	if err != nil {
		return session.CachedSession{}, err
	}
	wantHash := sha256.Sum256(secret)

	cached, err := c.getBySelector(ctx, selectorB64)
	if err != nil {
		return session.CachedSession{}, err
	}

	if len(cached.ValidatorHash) != len(wantHash) {
		return session.CachedSession{}, session.ErrSessionCacheRejected
	}
	if bytes.Equal(cached.ValidatorHash[:], wantHash[:]) {
		return cached, nil
	}
	return session.CachedSession{}, session.ErrSessionCacheRejected
}

func (c *KVSessionCache) getBySelector(
	ctx context.Context,
	selectorB64 string,
) (session.CachedSession, error) {
	data, err := c.client.Get(ctx, c.selectorCacheKey(selectorB64))
	if errors.Is(err, kv.ErrKeyNotFound) {
		return session.CachedSession{}, session.ErrSessionNotFound
	}
	if err != nil {
		return session.CachedSession{}, err
	}

	var rec sessionCacheRecord
	err = json.Unmarshal(data, &rec)
	if err != nil {
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
		c.deleteBySelector(ctx, selectorB64)
		return session.CachedSession{}, session.ErrSessionExpired
	}

	var validatorHash [32]byte
	if len(rec.ValidatorHash) == len(validatorHash) {
		copy(validatorHash[:], rec.ValidatorHash)
	}

	return session.CachedSession{
		SessionID:     sid,
		UserID:        uid,
		Email:         rec.Email,
		ExpiresAt:     exp,
		IssuedAt:      time.Unix(rec.IssuedAt, 0),
		ValidatorHash: validatorHash,
	}, nil
}

func sessionCacheTTL(expiresAt time.Time) time.Duration {
	ttl := time.Until(expiresAt)
	return min(ttl, session.MaxSessionCacheTTL)
}

// Set stores a snapshot keyed by the token's selector. The snapshot validator hash must
// match the wire token's validator secret.
func (c *KVSessionCache) Set(
	ctx context.Context,
	wireToken string,
	sess session.CachedSession,
) error {
	selectorB64, validatorB64, err := session.ParseWireSessionToken(wireToken)
	if err != nil {
		return err
	}
	secret, err := session.DecodeWireValidatorSecret(validatorB64)
	if err != nil {
		return err
	}
	want := sha256.Sum256(secret)
	if len(sess.ValidatorHash) != len(want) || !bytes.Equal(sess.ValidatorHash[:], want[:]) {
		return errors.New("session cache set: validator hash does not match wire token")
	}

	ttl := sessionCacheTTL(sess.ExpiresAt)
	if ttl <= 0 {
		return session.ErrSessionExpired
	}

	rec := sessionCacheRecord{
		SessionID:     sess.SessionID.String(),
		UserID:        sess.UserID.String(),
		Email:         sess.Email,
		ExpiresAt:     sess.ExpiresAt.Unix(),
		IssuedAt:      sess.IssuedAt.Unix(),
		ValidatorHash: sess.ValidatorHash[:],
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	return c.client.Set(ctx, c.selectorCacheKey(selectorB64), data, ttl)
}

func (c *KVSessionCache) Delete(ctx context.Context, wireToken string) error {
	selectorB64, _, err := session.ParseWireSessionToken(wireToken)
	if err != nil {
		return err
	}
	return c.deleteBySelector(ctx, selectorB64)
}

func (c *KVSessionCache) deleteBySelector(ctx context.Context, selectorB64 string) error {
	err := c.client.Delete(ctx, c.selectorCacheKey(selectorB64))
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}
	return err
}
