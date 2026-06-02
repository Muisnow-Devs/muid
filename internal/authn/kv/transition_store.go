package kv

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/kv"
	"sanzi.io/muid/pkg/shared/tracing"
)

const transitionSessionTTL = 15 * time.Minute

// KVAuthTransitionStore stores auth transitions in a KV backend.
type KVAuthTransitionStore struct {
	client kv.KVStore
}

func encodeSession(s session.AuthSession) ([]byte, error) {
	return json.Marshal(s)
}

func decodeSession(data []byte) (session.AuthSession, error) {
	var s session.AuthSession
	err := json.Unmarshal(data, &s)
	return s, err
}

// NewKVAuthTransitionStore returns a KV-backed transition store.
func NewKVAuthTransitionStore(kvStore kv.KVStore) session.AuthTransitionStore {
	return &KVAuthTransitionStore{client: kvStore}
}

func (s *KVAuthTransitionStore) key(id string) string {
	return "muid:auth:transition:" + id
}

func (k *KVAuthTransitionStore) Create(
	ctx context.Context,
	provider string,
	store session.SessionStore,
) (session.AuthSession, error) {
	id := uuid.New()
	now := time.Now()
	expiresAt := now.Add(transitionSessionTTL)

	sess := session.AuthSession{
		ID:        id,
		Provider:  provider,
		Store:     store,
		CreatedAt: now.Unix(),
		UpdatedAt: now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}

	key := k.key(sess.ID.String())
	ttl := time.Until(expiresAt)

	data, err := encodeSession(sess)
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

func (k *KVAuthTransitionStore) Delete(ctx context.Context, id uuid.UUID) error {
	key := k.key(id.String())
	err := k.client.Delete(ctx, key)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}

	return err
}

func (k *KVAuthTransitionStore) Get(
	ctx context.Context,
	id uuid.UUID,
) (session.AuthSession, error) {
	ctx, span := tracing.StartSpan(ctx, "authn.transition.get")
	defer span.End()

	key := k.key(id.String())
	data, err := k.client.Get(ctx, key)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return session.AuthSession{}, session.ErrSessionNotFound
	}
	if err != nil {
		return session.AuthSession{}, err
	}

	sess, err := decodeSession(data)
	if err != nil {
		return session.AuthSession{}, err
	}

	if time.Now().Unix() > sess.ExpiresAt {
		k.client.Delete(ctx, key)
		return session.AuthSession{}, session.ErrSessionExpired
	}

	return sess, nil
}

func (k *KVAuthTransitionStore) Update(
	ctx context.Context,
	id uuid.UUID,
	store session.SessionStore,
) error {
	key := k.key(id.String())

	// Ensure the session exists and is not expired before updating.
	existing, err := k.Get(ctx, id)
	if err != nil {
		return err
	}

	existing.Store = store
	existing.UpdatedAt = time.Now().Unix()

	// Defense-in-depth only.
	// Source of truth is KV TTL.
	ttl := time.Until(time.Unix(existing.ExpiresAt, 0))
	if ttl <= 0 {
		k.client.Delete(ctx, key)
		return session.ErrSessionExpired
	}

	data, err := encodeSession(existing)
	if err != nil {
		return err
	}

	return k.client.Set(ctx, key, data, ttl)
}
