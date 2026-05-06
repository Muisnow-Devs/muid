package kv

import (
	"context"
	"testing"

	"sanzi.io/muid/internal/session"
)

func TestKVAuthTransitionStore_CreateAndGet_Success(t *testing.T) {
	mockKV := newMockKVStore()
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

	fetched, err := store.Get(ctx, created.Provider, created.Id)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if fetched.Store.State != "init" {
		t.Errorf("expected state 'init', got '%s'", fetched.Store.State)
	}
}

func TestKVAuthTransitionStore_Get_NotFound(t *testing.T) {
	mockKV := newMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	_, err := store.Get(ctx, "password", "non-existent")
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestKVAuthTransitionStore_Update_Success(t *testing.T) {
	mockKV := newMockKVStore()
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
	err = store.Update(ctx, created.Provider, created.Id, storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fetched, _ := store.Get(ctx, created.Provider, created.Id)
	if fetched.Store.State != "authenticated" {
		t.Errorf("expected state 'authenticated', got '%s'", fetched.Store.State)
	}
}

func TestKVAuthTransitionStore_Update_NotFound(t *testing.T) {
	mockKV := newMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		State: "init",
	}

	err := store.Update(ctx, "password", "session-404", storeData)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestKVAuthTransitionStore_Delete(t *testing.T) {
	mockKV := newMockKVStore()
	store := NewKVAuthTransitionStore(mockKV)
	ctx := context.Background()

	storeData := session.SessionStore{
		State: "init",
	}

	created, err := store.Create(ctx, "password", storeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = store.Delete(ctx, created.Provider, created.Id)
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = store.Get(ctx, created.Provider, created.Id)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after deletion, got %v", err)
	}
}
