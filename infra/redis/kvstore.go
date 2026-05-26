package redis

import (
	"context"
	"time"

	goredis "github.com/go-redis/redis"
	"sanzi.io/muid/pkg/shared/kv"
)

const payloadSizeLimit = 64 * 1024 // 64KB

// RedisKVStore is a Redis-backed [KVStore].
type RedisKVStore struct {
	client *goredis.Client
}

// NewRedisKVStore opens a Redis client at redisAddr (host:port).
func NewRedisKVStore(redisAddr string, database int) KVStore {
	client := goredis.NewClient(&goredis.Options{
		Addr: redisAddr,
		DB:   database,
	})
	return &RedisKVStore{client: client}
}

// Close closes the Redis client.
func (r *RedisKVStore) Close() error {
	return r.client.Close()
}

func (r *RedisKVStore) Delete(ctx context.Context, key string) error {
	if key == "" {
		return kv.ErrInvalidKey
	}

	result := r.client.Del(key)
	if err := result.Err(); err != nil {
		return err
	}

	return nil
}

func (r *RedisKVStore) Get(ctx context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, kv.ErrInvalidKey
	}

	result := r.client.Get(key)
	if err := result.Err(); err != nil {
		if err == goredis.Nil {
			return nil, kv.ErrKeyNotFound
		}
		return nil, err
	}

	return result.Bytes()
}

func (r *RedisKVStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return kv.ErrInvalidKey
	}

	if len(value) > payloadSizeLimit {
		return kv.ErrPayloadTooLarge
	}

	result := r.client.Set(key, value, ttl)
	return result.Err()
}

func (r *RedisKVStore) SetNX(
	ctx context.Context,
	key string,
	value []byte,
	ttl time.Duration,
) (bool, error) {
	if key == "" {
		return false, kv.ErrInvalidKey
	}

	if len(value) > payloadSizeLimit {
		return false, kv.ErrPayloadTooLarge
	}

	result := r.client.SetNX(key, value, ttl)
	if err := result.Err(); err != nil {
		return false, err
	}

	return result.Val(), nil
}
