package kv

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/kv"
)

func randomWireToken(t *testing.T) (wire string, sum [32]byte) {
	t.Helper()
	sel := make([]byte, session.SelectorByteLength)
	sec := make([]byte, session.ValidatorByteLength)
	if _, err := rand.Read(sel); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(sec); err != nil {
		t.Fatal(err)
	}
	wire = base64.RawURLEncoding.EncodeToString(
		sel,
	) + "." + base64.RawURLEncoding.EncodeToString(
		sec,
	)
	sum = sha256.Sum256(sec)
	return wire, sum
}

func TestKVSessionCacheTTLNotBeyondExpiry(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	exp := time.Now().Add(2 * time.Minute)
	sid := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	uid := uuid.MustParse("00000000-0000-7000-8000-000000000002")
	wire, sum := randomWireToken(t)

	err := cache.Set(ctx, wire, session.CachedSession{
		SessionID:     sid,
		UserID:        uid,
		ExpiresAt:     exp,
		ValidatorHash: sum,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := cache.Get(ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != uid {
		t.Fatalf("user id: got %v", got.UserID)
	}

	_ = cache.Delete(ctx, wire)
	if _, err := cache.Get(ctx, wire); err == nil {
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

	wire, sum := randomWireToken(t)
	exp := time.Now().Add(7 * 24 * time.Hour)
	err := cache.Set(ctx, wire, session.CachedSession{
		SessionID:     uuid.New(),
		UserID:        uuid.New(),
		ExpiresAt:     exp,
		ValidatorHash: sum,
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

	wire, sum := randomWireToken(t)
	exp := time.Now().Add(time.Hour)

	err := cache.Set(ctx, wire, session.CachedSession{
		SessionID:     uuid.New(),
		UserID:        uuid.New(),
		ExpiresAt:     exp,
		ValidatorHash: sum,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := cache.Get(ctx, wire)
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

	wire, sum := randomWireToken(t)
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}

	sid := uuid.New()
	uid := uuid.New()
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
	key := (&KVSessionCache{client: store}).selectorCacheKey(selB64)
	err = store.Set(ctx, key, data, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cache.Get(ctx, wire)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Fatalf("Get expired: got %v want ErrSessionExpired", err)
	}
	if _, err := cache.Get(ctx, wire); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("expired entry should be deleted: got %v", err)
	}
}

func TestKVSessionCacheGetRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	wire, _ := randomWireToken(t)
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	key := (&KVSessionCache{client: store}).selectorCacheKey(selB64)
	err = store.Set(ctx, key, []byte("{not-json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cache.Get(ctx, wire)
	if err == nil {
		t.Fatal("expected error for malformed cache payload")
	}
}

func TestKVSessionCacheGetRejectsInvalidUUIDFields(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	wire, sum := randomWireToken(t)
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}

	rec := sessionCacheRecord{
		SessionID:     "not-a-uuid",
		UserID:        uuid.New().String(),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
		ValidatorHash: sum[:],
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	key := (&KVSessionCache{client: store}).selectorCacheKey(selB64)
	err = store.Set(ctx, key, data, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cache.Get(ctx, wire)
	if err == nil {
		t.Fatal("expected error for invalid session_id uuid")
	}
}

func TestKVSessionCacheExpiredRejected(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	wire, sum := randomWireToken(t)
	err := cache.Set(ctx, wire, session.CachedSession{
		SessionID:     uuid.New(),
		UserID:        uuid.New(),
		ExpiresAt:     time.Now().Add(-time.Minute),
		ValidatorHash: sum,
	})
	if err != session.ErrSessionExpired {
		t.Fatalf("Set with past expiry: got %v want ErrSessionExpired", err)
	}
}

func TestKVSessionCacheGetWrongValidatorNotFound(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	wireOK, sum := randomWireToken(t)
	selB64, _, err := session.ParseWireSessionToken(wireOK)
	if err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(time.Hour)
	err = cache.Set(ctx, wireOK, session.CachedSession{
		SessionID:     uuid.New(),
		UserID:        uuid.New(),
		ExpiresAt:     exp,
		ValidatorHash: sum,
	})
	if err != nil {
		t.Fatal(err)
	}

	wrongSec := make([]byte, session.ValidatorByteLength)
	if _, err := rand.Read(wrongSec); err != nil {
		t.Fatal(err)
	}
	wireBad := selB64 + "." + base64.RawURLEncoding.EncodeToString(wrongSec)

	_, err = cache.Get(ctx, wireBad)
	if !errors.Is(err, session.ErrSessionCacheRejected) {
		t.Fatalf("wrong validator: got %v", err)
	}

	got, err := cache.Get(ctx, wireOK)
	if err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if !bytes.Equal(got.ValidatorHash[:], sum[:]) {
		t.Fatal("validator hash mismatch on valid read")
	}
}

func TestKVSessionCacheSetRejectsMismatchedValidatorSnapshot(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	wire, sum := randomWireToken(t)
	var wrongSum [32]byte
	copy(wrongSum[:], sum[:])
	wrongSum[0] ^= 0xff

	err := cache.Set(ctx, wire, session.CachedSession{
		SessionID:     uuid.New(),
		UserID:        uuid.New(),
		ExpiresAt:     time.Now().Add(time.Hour),
		ValidatorHash: wrongSum,
	})
	if err == nil {
		t.Fatal("expected error when snapshot hash does not match wire token")
	}
}
