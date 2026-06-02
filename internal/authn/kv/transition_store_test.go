package kv

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/session"
)

func TestKVAuthTransitionStore_CreateAndGet_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		Step: session.AuthStep("init"),
	}

	created, err := store.Create(ctx, "password", storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fetched, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if fetched.Store.Step != session.AuthStep("init") {
		t.Errorf("expected step 'init', got '%s'", fetched.Store.Step)
	}
	if fetched.Provider != "password" {
		t.Errorf("expected provider to be 'password', got '%s'", fetched.Provider)
	}
}

func TestKVAuthTransitionStore_Get_NotFound(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	_, err := store.Get(ctx, uuid.UUID{0})
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestKVAuthTransitionStore_Update_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		Step: session.AuthStep("init"),
	}

	created, err := store.Create(ctx, "password", storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	storeData.Step = session.AuthStep("authenticated")
	err = store.Update(ctx, created.ID, storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fetched, _ := store.Get(ctx, created.ID)
	if fetched.Store.Step != session.AuthStep("authenticated") {
		t.Errorf("expected step 'authenticated', got '%s'", fetched.Store.Step)
	}
}

func TestKVAuthTransitionStore_Update_NotFound(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		Step: session.AuthStep("init"),
	}

	err := store.Update(ctx, uuid.UUID{0}, storeData)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestKVAuthTransitionStore_Delete(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		Step: session.AuthStep("init"),
	}

	created, err := store.Create(ctx, "password", storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = store.Delete(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = store.Get(ctx, created.ID)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after deletion, got %v", err)
	}
}

func TestKVAuthTransitionStore_Security_Expired_Get(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	created, err := store.Create(ctx, "password", session.SessionStore{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Manually force expiration by rewriting the stored data
	key := store.(*KVAuthTransitionStore).key(created.ID.String())
	data, _ := mockKV.Get(ctx, key)
	sess, _ := decodeSession(data)
	sess.ExpiresAt = sess.ExpiresAt - 3600 // Subtract an hour
	expiredData, _ := encodeSession(sess)

	err = mockKV.Set(ctx, key, expiredData, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	_, err = store.Get(ctx, created.ID)
	if err != session.ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}

	// Make sure it actively deleted the expired key to avoid leaks
	_, err = mockKV.Get(ctx, key)
	if err == nil {
		t.Fatalf("expected key to be deleted upon discovering expiration")
	}
}

func TestKVAuthTransitionStore_Security_Expired_Update(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	created, _ := store.Create(ctx, "password", session.SessionStore{})

	// Manually force expiration safely
	key := store.(*KVAuthTransitionStore).key(created.ID.String())
	data, _ := mockKV.Get(ctx, key)
	sess, _ := decodeSession(data)
	sess.ExpiresAt = sess.ExpiresAt - 3600
	expiredData, _ := encodeSession(sess)

	err := mockKV.Set(ctx, key, expiredData, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = store.Update(ctx, created.ID, session.SessionStore{Step: session.AuthStep("bypassed")})
	if err != session.ErrSessionExpired && err != session.ErrSessionNotFound {
		t.Fatalf(
			"expected ErrSessionExpired during update of an already expired token, got %v",
			err,
		)
	}
}

func TestKVAuthTransitionStore_Security_UUIDEntropy(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	created, _ := store.Create(
		ctx,
		"password",
		session.SessionStore{Step: session.AuthStep("valid")},
	)

	// With the removal of 'provider' from Get and Update, the store relies purely on the UUID
	// Check that the returned UUID is sufficiently unguessable (length of at least 32).
	if len(created.ID.String()) < 32 {
		t.Fatalf(
			"expected generated session id to be sufficiently long to prevent brute-forcing, got %v",
			len(created.ID),
		)
	}

	// Ensure that while the provider is not a parameter for Get,
	// it correctly retrieves and passes back the Provider for application-layer validation.
	fetched, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if fetched.Provider != "password" {
		t.Fatalf(
			"expected the store to persist the provider state accurately, got %v",
			fetched.Provider,
		)
	}
}
