package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/session"
)

type mapSessionCache struct {
	entries map[string]session.CachedSession
}

func (m *mapSessionCache) Get(
	_ context.Context,
	selectorKey string,
) (session.CachedSession, error) {
	sess, ok := m.entries[selectorKey]
	if !ok {
		return session.CachedSession{}, session.ErrSessionNotFound
	}
	return sess, nil
}

func (m *mapSessionCache) Set(
	_ context.Context,
	selectorKey string,
	sess session.CachedSession,
) error {
	m.entries[selectorKey] = sess
	return nil
}

func (m *mapSessionCache) Delete(_ context.Context, selectorKey string) error {
	delete(m.entries, selectorKey)
	return nil
}

func TestResolveSessionTokenCacheRequiresValidator(t *testing.T) {
	t.Parallel()

	selectorBytes := make([]byte, SelectorLength)
	validatorSecret := make([]byte, ValidatorLength)
	if _, err := rand.Read(selectorBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(validatorSecret); err != nil {
		t.Fatal(err)
	}

	selectorB64 := base64.RawURLEncoding.EncodeToString(selectorBytes)
	validatorB64 := base64.RawURLEncoding.EncodeToString(validatorSecret)
	wireOK := selectorB64 + "." + validatorB64

	wrongValidator := make([]byte, ValidatorLength)
	if _, err := rand.Read(wrongValidator); err != nil {
		t.Fatal(err)
	}
	wireBadValidator := selectorB64 + "." + base64.RawURLEncoding.EncodeToString(wrongValidator)

	sum := sha256.Sum256(validatorSecret)
	sid := uuid.MustParse("00000000-0000-7000-8000-000000000010")
	uid := uuid.MustParse("00000000-0000-7000-8000-000000000011")
	exp := time.Now().Add(time.Hour)

	cache := &mapSessionCache{entries: map[string]session.CachedSession{
		selectorB64: {
			SessionID:     sid,
			UserID:        uid,
			ExpiresAt:     exp,
			ValidatorHash: sum,
		},
	}}

	svc := &sessionService{
		store: &Store{SessionCache: cache},
	}

	got, err := svc.ResolveSessionToken(context.Background(), wireOK)
	if err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if got.SessionID != sid || got.UserID != uid {
		t.Fatalf("resolved session: %+v", got)
	}

	_, err = svc.ResolveSessionToken(context.Background(), wireBadValidator)
	if err == nil {
		t.Fatal("expected error for wrong validator with cache hit")
	}
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("wrong validator: got %v want ErrSessionNotFound", err)
	}
}

func TestResolveSessionTokenCacheWrongValidatorNoSessionLeak(t *testing.T) {
	t.Parallel()

	selectorBytes := make([]byte, SelectorLength)
	validatorSecret := make([]byte, ValidatorLength)
	if _, err := rand.Read(selectorBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(validatorSecret); err != nil {
		t.Fatal(err)
	}

	selectorB64 := base64.RawURLEncoding.EncodeToString(selectorBytes)
	wireOK := selectorB64 + "." + base64.RawURLEncoding.EncodeToString(validatorSecret)

	wrongValidator := make([]byte, ValidatorLength)
	if _, err := rand.Read(wrongValidator); err != nil {
		t.Fatal(err)
	}
	wireBadValidator := selectorB64 + "." + base64.RawURLEncoding.EncodeToString(wrongValidator)

	sum := sha256.Sum256(validatorSecret)
	victimUID := uuid.MustParse("00000000-0000-7000-8000-000000000012")
	attackerUID := uuid.MustParse("00000000-0000-7000-8000-000000000013")

	cache := &mapSessionCache{entries: map[string]session.CachedSession{
		selectorB64: {
			SessionID:     uuid.MustParse("00000000-0000-7000-8000-000000000014"),
			UserID:        victimUID,
			ExpiresAt:     time.Now().Add(time.Hour),
			ValidatorHash: sum,
		},
	}}

	svc := &sessionService{store: &Store{SessionCache: cache}}

	_, err := svc.ResolveSessionToken(context.Background(), wireBadValidator)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("wrong validator: got %v", err)
	}

	got, err := svc.ResolveSessionToken(context.Background(), wireOK)
	if err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if got.UserID != victimUID {
		t.Fatalf("leaked or wrong user: got %v want %v", got.UserID, victimUID)
	}
	if got.UserID == attackerUID {
		t.Fatal("must not return attacker user id")
	}
}

func TestResolveSessionTokenCacheValidatorMismatchSkipsDB(t *testing.T) {
	t.Parallel()

	selectorBytes := make([]byte, SelectorLength)
	validatorSecret := make([]byte, ValidatorLength)
	if _, err := rand.Read(selectorBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(validatorSecret); err != nil {
		t.Fatal(err)
	}

	selectorB64 := base64.RawURLEncoding.EncodeToString(selectorBytes)
	wire := selectorB64 + "." + base64.RawURLEncoding.EncodeToString(validatorSecret)

	// Cache entry with zero validator hash: mismatch returns not-found without DB lookup.
	cache := &mapSessionCache{entries: map[string]session.CachedSession{
		selectorB64: {
			SessionID: uuid.New(),
			UserID:    uuid.New(),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}}
	svc := &sessionService{store: &Store{SessionCache: cache}}

	_, err := svc.ResolveSessionToken(context.Background(), wire)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("validator mismatch with cache present: got %v", err)
	}
}
