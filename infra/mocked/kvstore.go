package mocked

import (
	"context"
	"time"

	"sanzi.io/muid/pkg/shared/kv"
)

type mockItem struct {
	value      []byte
	expiration time.Time
}

// MockKVStore is an in-memory [KVStore] for tests.
type MockKVStore struct {
	store map[string]mockItem
}

// NewMockKVStore returns an empty in-memory [KVStore].
func NewMockKVStore() KVStore {
	return &MockKVStore{
		store: make(map[string]mockItem),
	}
}

func (m *MockKVStore) Get(ctx context.Context, key string) ([]byte, error) {
	item, ok := m.store[key]
	if !ok {
		return nil, kv.ErrKeyNotFound
	}
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		delete(m.store, key)
		return nil, kv.ErrKeyNotFound
	}
	return item.value, nil
}

func (m *MockKVStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.store[key] = mockItem{
		value:      value,
		expiration: exp,
	}
	return nil
}

func (m *MockKVStore) SetNX(
	ctx context.Context,
	key string,
	value []byte,
	ttl time.Duration,
) (bool, error) {
	item, ok := m.store[key]
	if ok && (item.expiration.IsZero() || !time.Now().After(item.expiration)) {
		return false, nil
	}
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.store[key] = mockItem{
		value:      value,
		expiration: exp,
	}
	return true, nil
}

func (m *MockKVStore) Delete(ctx context.Context, key string) error {
	delete(m.store, key)
	return nil
}

func (m *MockKVStore) Close() error {
	return nil
}
