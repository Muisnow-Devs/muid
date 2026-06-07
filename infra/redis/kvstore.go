package redis

import (
	"context"
	"time"

	goredis "github.com/go-redis/redis"
	"sanzi.io/muid/infra/redis/scripts"
	"sanzi.io/muid/pkg/shared/kv"
)

const payloadSizeLimit = 64 * 1024 // 64KB

// redisKVStore is a Redis-backed [KVStore].
type redisKVStore struct {
	client *goredis.Client
}

// NewredisKVStore opens a Redis client at redisAddr (host:port).
func NewRedisKVStore(redisAddr string, database int) KVStore {
	client := goredis.NewClient(&goredis.Options{
		Addr: redisAddr,
		DB:   database,
	})
	return &redisKVStore{client: client}
}

// Close closes the Redis client.
func (r *redisKVStore) Close() error {
	return r.client.Close()
}

func (r *redisKVStore) Delete(ctx context.Context, key string) error {
	if key == "" {
		return kv.ErrInvalidKey
	}

	result := r.client.Del(key)
	if err := result.Err(); err != nil {
		return err
	}

	return nil
}

func (r *redisKVStore) Get(ctx context.Context, key string) ([]byte, error) {
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

func (r *redisKVStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return kv.ErrInvalidKey
	}

	if len(value) > payloadSizeLimit {
		return kv.ErrPayloadTooLarge
	}

	result := r.client.Set(key, value, ttl)
	return result.Err()
}

func (r *redisKVStore) SetNX(
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

func (r *redisKVStore) Exists(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, kv.ErrInvalidKey
	}

	result := r.client.Exists(key)
	if err := result.Err(); err != nil {
		return false, err
	}

	return result.Val() > 0, nil
}

func (r *redisKVStore) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if key == "" {
		return kv.ErrInvalidKey
	}

	result := r.client.Expire(key, ttl)
	return result.Err()
}

func (r *redisKVStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	if key == "" {
		return 0, kv.ErrInvalidKey
	}

	result := r.client.TTL(key)
	return result.Val(), result.Err()
}

func (r *redisKVStore) Increment(ctx context.Context, key string) (int64, error) {
	if key == "" {
		return 0, kv.ErrInvalidKey
	}

	result := r.client.Incr(key)
	return result.Val(), result.Err()
}

func (r *redisKVStore) CompareAndDelete(
	ctx context.Context,
	key string,
	expected []byte,
) (bool, error) {
	if key == "" {
		return false, kv.ErrInvalidKey
	}

	result, err := scripts.CompareAndDeleteScript.Run(r.client, []string{key}, expected).Int()
	if err != nil {
		return false, err
	}

	return result == 1, nil
}
