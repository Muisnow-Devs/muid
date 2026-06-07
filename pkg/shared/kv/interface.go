package kv

import (
	"context"
	"time"
)

type KVStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	TTL(ctx context.Context, key string) (time.Duration, error)
	Increment(ctx context.Context, key string) (int64, error)
}

type AtomicKVStore interface {
	KVStore

	CompareAndDelete(
		ctx context.Context,
		key string,
		expected []byte,
	) (bool, error)
}
