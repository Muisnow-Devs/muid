package kv

import (
	"context"
	"testing"

	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/infra/mocked"
)

func TestKVAuthTransitionStore_CreateAndGet_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		State: "init",
	}

	created, err := store.Create(ctx, "password", storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if created.Id == "" {
		t.Errorf("expected session id to be generated, got empty")
	}

	fetched, err := store.Get(ctx, created.Id)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if fetched.Store.State != "init" {
		t.Errorf("expected state 'init', got '%s'", fetched.Store.State)
	}
	if fetched.Provider != "password" {
		t.Errorf("expected provider to be 'password', got '%s'", fetched.Provider)
	}
}

func TestKVAuthTransitionStore_Get_NotFound(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	_, err := store.Get(ctx, "non-existent")
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestKVAuthTransitionStore_Update_Success(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		State: "init",
	}

	created, err := store.Create(ctx, "password", storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	storeData.State = "authenticated"
	err = store.Update(ctx, created.Id, storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fetched, _ := store.Get(ctx, created.Id)
	if fetched.Store.State != "authenticated" {
		t.Errorf("expected state 'authenticated', got '%s'", fetched.Store.State)
	}
}

func TestKVAuthTransitionStore_Update_NotFound(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		State: "init",
	}

	err := store.Update(ctx, "session-404", storeData)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestKVAuthTransitionStore_Delete(t *testing.T) {
	mockKV := mocked.NewMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		State: "init",
	}

	created, err := store.Create(ctx, "password", storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = store.Delete(ctx, created.Id)
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = store.Get(ctx, created.Id)
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
	key := store.(KVAuthTransitionStore).key(created.Id)
	data, _ := mockKV.Get(ctx, key)
	sess, _ := decode(data)
	sess.ExpiresAt = sess.ExpiresAt - 3600 // Subtract an hour
	expiredData, _ := encode(sess)

	err = mockKV.Set(ctx, key, expiredData, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	_, err = store.Get(ctx, created.Id)
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
	key := store.(KVAuthTransitionStore).key(created.Id)
	data, _ := mockKV.Get(ctx, key)
	sess, _ := decode(data)
	sess.ExpiresAt = sess.ExpiresAt - 3600
	expiredData, _ := encode(sess)

	err := mockKV.Set(ctx, key, expiredData, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = store.Update(ctx, created.Id, session.SessionStore{State: "bypassed"})
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

	created, _ := store.Create(ctx, "password", session.SessionStore{State: "valid"})

	// With the removal of 'provider' from Get and Update, the store relies purely on the UUID
	// Check that the returned UUID is sufficiently unguessable (length of at least 32).
	if len(created.Id) < 32 {
		t.Fatalf(
			"expected generated session id to be sufficiently long to prevent brute-forcing, got %v",
			len(created.Id),
		)
	}

	// Ensure that while the provider is not a parameter for Get,
	// it correctly retrieves and passes back the Provider for application-layer validation.
	fetched, err := store.Get(ctx, created.Id)
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
