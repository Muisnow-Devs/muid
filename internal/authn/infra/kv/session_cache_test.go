package kv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/kv"
)

func TestKVSessionCacheTTLNotBeyondExpiry(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	exp := time.Now().Add(2 * time.Minute)
	sid := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	uid := uuid.MustParse("00000000-0000-7000-8000-000000000002")
	selectorKey := "test-selector-b64"

	var validatorHash [32]byte
	err := cache.Set(ctx, selectorKey, session.CachedSession{
		SessionID:     sid,
		UserID:        uid,
		ExpiresAt:     exp,
		ValidatorHash: validatorHash,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := cache.Get(ctx, selectorKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != uid {
		t.Fatalf("user id: got %v", got.UserID)
	}

	_ = cache.Delete(ctx, selectorKey)
	if _, err := cache.Get(ctx, selectorKey); err == nil {
		t.Fatal("expected cache miss after delete")
	}
}

func TestSessionCacheTTLCapsAtOneHour(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresIn time.Duration
		wantTTL   time.Duration
	}{
		{
			name:      "short session uses time until expiry",
			expiresIn: 15 * time.Minute,
			wantTTL:   15 * time.Minute,
		},
		{
			name:      "long session capped at one hour",
			expiresIn: 7 * 24 * time.Hour,
			wantTTL:   session.MaxSessionCacheTTL,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sessionCacheTTL(time.Now().Add(tc.expiresIn))
			// Allow a small skew because sessionCacheTTL uses time.Until.
			if got < tc.wantTTL-time.Second || got > tc.wantTTL+time.Second {
				t.Fatalf("sessionCacheTTL: got %v want ~%v", got, tc.wantTTL)
			}
		})
	}
}

func TestKVSessionCacheSetTTLCapped(t *testing.T) {
	t.Parallel()

	store := &ttlCaptureKV{KVStore: mocked.NewMockKVStore()}
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	exp := time.Now().Add(7 * 24 * time.Hour)
	err := cache.Set(ctx, "sel", session.CachedSession{
		SessionID: uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.lastTTL < session.MaxSessionCacheTTL-time.Second ||
		store.lastTTL > session.MaxSessionCacheTTL+time.Second {
		t.Fatalf("Set TTL: got %v want ~%v", store.lastTTL, session.MaxSessionCacheTTL)
	}
}

func TestKVSessionCacheRoundTripsValidatorHash(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	secret := []byte("validator-secret-for-cache-test!!")
	sum := sha256.Sum256(secret)
	selectorKey := "roundtrip-selector"
	exp := time.Now().Add(time.Hour)

	err := cache.Set(ctx, selectorKey, session.CachedSession{
		SessionID:     uuid.New(),
		UserID:        uuid.New(),
		ExpiresAt:     exp,
		ValidatorHash: sum,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := cache.Get(ctx, selectorKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.ValidatorHash != sum {
		t.Fatalf("validator hash: got %x want %x", got.ValidatorHash, sum)
	}
}

type ttlCaptureKV struct {
	kv.KVStore
	lastTTL time.Duration
}

func (c *ttlCaptureKV) Set(
	ctx context.Context,
	key string,
	value []byte,
	ttl time.Duration,
) error {
	c.lastTTL = ttl
	return c.KVStore.Set(ctx, key, value, ttl)
}

func TestKVSessionCacheGetRejectsExpiredEntry(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	selectorKey := "expired-get-selector"
	sid := uuid.New()
	uid := uuid.New()
	sum := sha256.Sum256([]byte("validator-secret-for-expired-get"))
	expiredAt := time.Now().Add(-2 * time.Minute)

	rec := sessionCacheRecord{
		SessionID:     sid.String(),
		UserID:        uid.String(),
		ExpiresAt:     expiredAt.Unix(),
		ValidatorHash: sum[:],
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	key := (&KVSessionCache{client: store}).cacheKey(selectorKey)
	if err := store.Set(ctx, key, data, time.Hour); err != nil {
		t.Fatal(err)
	}

	_, err = cache.Get(ctx, selectorKey)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Fatalf("Get expired: got %v want ErrSessionExpired", err)
	}
	if _, err := cache.Get(ctx, selectorKey); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("expired entry should be deleted: got %v", err)
	}
}

func TestKVSessionCacheGetRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	selectorKey := "malformed-json"
	key := (&KVSessionCache{client: store}).cacheKey(selectorKey)
	if err := store.Set(ctx, key, []byte("{not-json"), time.Hour); err != nil {
		t.Fatal(err)
	}

	_, err := cache.Get(ctx, selectorKey)
	if err == nil {
		t.Fatal("expected error for malformed cache payload")
	}
}

func TestKVSessionCacheGetRejectsInvalidUUIDFields(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	selectorKey := "bad-uuid-fields"
	rec := sessionCacheRecord{
		SessionID: "not-a-uuid",
		UserID:    uuid.New().String(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	key := (&KVSessionCache{client: store}).cacheKey(selectorKey)
	if err := store.Set(ctx, key, data, time.Hour); err != nil {
		t.Fatal(err)
	}

	_, err = cache.Get(ctx, selectorKey)
	if err == nil {
		t.Fatal("expected error for invalid session_id uuid")
	}
}

func TestKVSessionCacheExpiredRejected(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	selectorKey := "expired-selector"
	err := cache.Set(ctx, selectorKey, session.CachedSession{
		SessionID: uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != session.ErrSessionExpired {
		t.Fatalf("Set with past expiry: got %v want ErrSessionExpired", err)
	}
}
