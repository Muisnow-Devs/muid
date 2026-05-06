package kv

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/kv"
)

const (
	TRANSITION_SESSION_TTL = 15 * time.Minute
)

type KVAuthTransitionStore struct {
	client kv.KVStore
}

func encode(s session.AuthSession) ([]byte, error) {
	return json.Marshal(s)
}

func decode(data []byte) (session.AuthSession, error) {
	var s session.AuthSession
	err := json.Unmarshal(data, &s)
	return s, err
}

func NewKVAuthTransitionStore(kvStore kv.KVStore) session.AuthTransitionStore {
	return KVAuthTransitionStore{client: kvStore}
}

func (s KVAuthTransitionStore) key(id string) string {
	return "muid:auth:transition:" + id
}

func (k KVAuthTransitionStore) Create(ctx context.Context, provider string, store session.SessionStore) (session.AuthSession, error) {
	id := uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(TRANSITION_SESSION_TTL)

	sess := session.AuthSession{
		Id:        id,
		Provider:  provider,
		Store:     store,
		CreatedAt: now.Unix(),
		UpdatedAt: now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}

	key := k.key(sess.Id)
	ttl := time.Until(time.Unix(sess.ExpiresAt, 0))

	data, err := encode(sess)
	if err != nil {
		return session.AuthSession{}, err
	}

	ok, err := k.client.SetNX(ctx, key, data, ttl)
	if err != nil {
		return session.AuthSession{}, err
	}
	if !ok {
		return session.AuthSession{}, session.ErrSessionExists
	}

	return sess, nil
}

func (k KVAuthTransitionStore) Delete(ctx context.Context, provider, id string) error {
	key := k.key(id)
	err := k.client.Delete(ctx, key)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}

	return err
}

func (k KVAuthTransitionStore) Get(ctx context.Context, provider, id string) (session.AuthSession, error) {
	key := k.key(id)
	data, err := k.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, kv.ErrKeyNotFound) {
			return session.AuthSession{}, session.ErrSessionNotFound
		}
		return session.AuthSession{}, err
	}

	sess, err := decode(data)
	if err != nil {
		return session.AuthSession{}, err
	}

	if time.Now().Unix() > sess.ExpiresAt {
		_ = k.client.Delete(ctx, key)
		return session.AuthSession{}, session.ErrSessionExpired
	}

	return sess, nil
}

func (k KVAuthTransitionStore) Update(ctx context.Context, provider, id string, store session.SessionStore) error {
	key := k.key(id)

	// Ensure the session exists and is not expired before updating
	existing, err := k.Get(ctx, provider, id)
	if err != nil {
		return err
	}

	existing.Store = store
	existing.UpdatedAt = time.Now().Unix()

	// Defense-in-depth only.
	// Source of truth is KV TTL.
	ttl := time.Until(time.Unix(existing.ExpiresAt, 0))
	if ttl <= 0 {
		_ = k.client.Delete(ctx, key)
		return session.ErrSessionExpired
	}

	data, err := encode(existing)
	if err != nil {
		return err
	}

	return k.client.Set(ctx, key, data, ttl)
}
