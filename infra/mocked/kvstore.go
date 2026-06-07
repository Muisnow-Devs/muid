package mocked

import (
	"bytes"
	"context"
	"strconv"
	"sync"
	"time"

	"sanzi.io/muid/pkg/shared/kv"
)

type mockItem struct {
	value      []byte
	expiration time.Time
}

// MockKVStore is an in-memory [kv.AtomicKVStore] for tests.
type MockKVStore struct {
	mu    sync.Mutex
	store map[string]mockItem
}

// NewMockKVStore returns an empty in-memory [kv.AtomicKVStore].
func NewMockKVStore() KVStore {
	return &MockKVStore{
		store: make(map[string]mockItem),
	}
}

func (m *MockKVStore) get(key string) (mockItem, bool) {
	item, ok := m.store[key]
	if !ok {
		return mockItem{}, false
	}
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		delete(m.store, key)
		return mockItem{}, false
	}
	return item, true
}

func (m *MockKVStore) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.get(key)
	if !ok {
		return nil, kv.ErrKeyNotFound
	}
	return item.value, nil
}

func (m *MockKVStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.store[key] = mockItem{value: value, expiration: exp}
	return nil
}

func (m *MockKVStore) SetNX(
	ctx context.Context,
	key string,
	value []byte,
	ttl time.Duration,
) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.get(key); ok {
		return false, nil
	}
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.store[key] = mockItem{value: value, expiration: exp}
	return true, nil
}

func (m *MockKVStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.store, key)
	return nil
}

func (m *MockKVStore) Exists(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.get(key)
	return ok, nil
}

func (m *MockKVStore) Expire(ctx context.Context, key string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.get(key)
	if !ok {
		return kv.ErrKeyNotFound
	}
	if ttl > 0 {
		item.expiration = time.Now().Add(ttl)
	} else {
		item.expiration = time.Time{}
	}
	m.store[key] = item
	return nil
}

func (m *MockKVStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.get(key)
	if !ok {
		return 0, kv.ErrKeyNotFound
	}
	if item.expiration.IsZero() {
		return -1, nil // no expiry
	}
	return time.Until(item.expiration), nil
}

// Increment atomically increments a counter stored as a decimal integer string.
// The key is created with value 1 if it does not exist.
func (m *MockKVStore) Increment(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var n int64
	if item, ok := m.get(key); ok {
		parsed, err := strconv.ParseInt(string(item.value), 10, 64)
		if err != nil {
			return 0, err
		}
		n = parsed
	}
	n++
	existing := m.store[key]
	m.store[key] = mockItem{
		value:      []byte(strconv.FormatInt(n, 10)),
		expiration: existing.expiration,
	}
	return n, nil
}

// CompareAndDelete deletes the key only if its current value equals expected.
// Returns true when the key was found and deleted.
func (m *MockKVStore) CompareAndDelete(
	ctx context.Context,
	key string,
	expected []byte,
) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.get(key)
	if !ok {
		return false, nil
	}
	if !bytes.Equal(item.value, expected) {
		return false, nil
	}
	delete(m.store, key)
	return true, nil
}

func (m *MockKVStore) Close() error {
	return nil
}
