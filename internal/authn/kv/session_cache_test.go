package kv

import (
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
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}

	err = cache.Set(ctx, selB64, session.CachedSession{
		SessionID:      sid,
		UserID:         uid,
		ExpiresAt:      exp,
		AbsoluteExpiry: exp.Add(time.Hour),
		ValidatorHash:  sum,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, ok, err := cache.Get(ctx, selB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.UserID != uid {
		t.Fatalf("user id: got %v", got.UserID)
	}

	err = cache.Delete(ctx, selB64)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := cache.Get(ctx, selB64); ok || err != nil {
		t.Fatalf("expected cache miss after delete, got ok=%v err=%v", ok, err)
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
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(7 * 24 * time.Hour)
	err = cache.Set(ctx, selB64, session.CachedSession{
		SessionID:      uuid.New(),
		UserID:         uuid.New(),
		ExpiresAt:      exp,
		AbsoluteExpiry: exp.Add(time.Hour),
		ValidatorHash:  sum,
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
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	err = cache.Set(ctx, selB64, session.CachedSession{
		SessionID:      uuid.New(),
		UserID:         uuid.New(),
		ExpiresAt:      exp,
		AbsoluteExpiry: exp.Add(time.Hour),
		ValidatorHash:  sum,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, ok, err := cache.Get(ctx, selB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected cache hit")
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

	sid := uuid.New().String()
	selKey := (&KVSessionCache{client: store}).selectorCacheKey(selB64)
	err = store.Set(ctx, selKey, []byte(sid), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	idKey := (&KVSessionCache{client: store}).idCacheKey(sid)
	err = store.Set(ctx, idKey, []byte("{not-json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, ok, err := cache.Get(ctx, selB64)
	if ok {
		t.Fatal("expected cache miss for malformed JSON")
	}
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

	sidStr := uuid.New().String()
	selKey := (&KVSessionCache{client: store}).selectorCacheKey(selB64)
	err = store.Set(ctx, selKey, []byte(sidStr), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	rec := sessionCacheRecord{
		SessionID:     "not-a-uuid",
		UserID:        uuid.New().String(),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
		ValidatorHash: sum,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	idKey := (&KVSessionCache{client: store}).idCacheKey(sidStr)
	err = store.Set(ctx, idKey, data, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, ok, err := cache.Get(ctx, selB64)
	if ok {
		t.Fatal("expected cache miss for invalid session_id")
	}
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
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	err = cache.Set(ctx, selB64, session.CachedSession{
		SessionID:      uuid.New(),
		UserID:         uuid.New(),
		ExpiresAt:      time.Now().Add(-time.Minute),
		AbsoluteExpiry: time.Now().Add(time.Hour),
		ValidatorHash:  sum,
	})
	if err != session.ErrSessionExpired {
		t.Fatalf("Set with past expiry: got %v want ErrSessionExpired", err)
	}
}

func TestKVSessionCacheDeleteByID(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	exp := time.Now().Add(time.Hour)
	sid := uuid.New()
	uid := uuid.New()
	wire, sum := randomWireToken(t)
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}

	err = cache.Set(ctx, selB64, session.CachedSession{
		SessionID:      sid,
		UserID:         uid,
		ExpiresAt:      exp,
		AbsoluteExpiry: exp.Add(time.Hour),
		ValidatorHash:  sum,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify cache hit
	_, ok, err := cache.Get(ctx, selB64)
	if err != nil || !ok {
		t.Fatalf("expected cache hit, got ok=%v err=%v", ok, err)
	}

	// Delete by ID
	err = cache.DeleteByID(ctx, sid.String())
	if err != nil {
		t.Fatal(err)
	}

	// Verify cache miss (due to self-cleaning)
	_, ok, err = cache.Get(ctx, selB64)
	if err != nil || ok {
		t.Fatalf("expected cache miss after delete by ID, got ok=%v err=%v", ok, err)
	}

	// Verify selector reference key is cleaned up in the raw store
	selKey := (&KVSessionCache{client: store}).selectorCacheKey(selB64)
	_, err = store.Get(ctx, selKey)
	if !errors.Is(err, kv.ErrKeyNotFound) {
		t.Fatalf("expected selector key to be cleaned up in store, got err=%v", err)
	}
}

func TestKVSessionCacheStaleReferenceCleanup(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	cache := NewKVSessionCache(store)
	ctx := context.Background()

	wire, _ := randomWireToken(t)
	selB64, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}

	sidStr := uuid.New().String()
	selKey := (&KVSessionCache{client: store}).selectorCacheKey(selB64)
	err = store.Set(ctx, selKey, []byte(sidStr), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Do NOT set the ID key, leaving the selector reference stale

	// Get should detect stale reference, delete it, and return miss
	_, ok, err := cache.Get(ctx, selB64)
	if ok || err != nil {
		t.Fatalf("expected cache miss, got ok=%v err=%v", ok, err)
	}

	// Verify selector reference key has been deleted
	_, err = store.Get(ctx, selKey)
	if !errors.Is(err, kv.ErrKeyNotFound) {
		t.Fatalf("expected selector key to be cleaned up, got err=%v", err)
	}
}
