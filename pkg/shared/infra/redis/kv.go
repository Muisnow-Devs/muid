package redis

import (
	"context"
	"time"

	"github.com/go-redis/redis"
	"sanzi.io/muid/pkg/shared/kv"
)

const (
	PAYLOAD_SIZE_LIMIT = 64 * 1024 // 64KB
)

type RedisKVStore struct {
	client *redis.Client
}

func NewRedisKVStore(redisUrl string) kv.KVStore {
	client := redis.NewClient(&redis.Options{
		Addr: redisUrl,
	})

	return &RedisKVStore{client: client}
}

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
		if err == redis.Nil {
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

	if len(value) > PAYLOAD_SIZE_LIMIT {
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

	if len(value) > PAYLOAD_SIZE_LIMIT {
		return false, kv.ErrPayloadTooLarge
	}

	result := r.client.SetNX(key, value, ttl)
	if err := result.Err(); err != nil {
		return false, err
	}

	return result.Val(), nil
}
