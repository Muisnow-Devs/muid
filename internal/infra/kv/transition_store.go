package kv

import (
	"context"
	"encoding/json"
	"time"

	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/kv"
)

type KVAuthTransitionStore struct {
	client kv.KVStore
}

func encode(session session.AuthSession) ([]byte, error) {
	return json.Marshal(session)
}

func decode(data []byte) (session.AuthSession, error) {
	var session session.AuthSession
	err := json.Unmarshal(data, &session)
	return session, err
}

func NewKVAuthTransitionStore(kvStore kv.KVStore) session.AuthTransitionStore {
	return KVAuthTransitionStore{client: kvStore}
}

func (KVAuthTransitionStore) key(provider, id string) string {
	return "muid:auth:transition:" + provider + ":" + id
}

func (k KVAuthTransitionStore) Create(ctx context.Context, session session.AuthSession) (session.AuthSession, error) {
	key := k.key(session.Provider, session.Id)
	ttl := time.Until(time.Unix(session.ExpiresAt, 0))
	if ttl <= 0 {
		return session.AuthSession{}, ErrSessionExpired
	}
}

func (k KVAuthTransitionStore) Delete(ctx context.Context, provider, id string) error {
	panic("unimplemented")
}

func (k KVAuthTransitionStore) Get(ctx context.Context, provider, id string) (session.AuthSession, error) {
	panic("unimplemented")
}

func (k KVAuthTransitionStore) Update(ctx context.Context, session session.AuthSession) error {
	panic("unimplemented")
}

func (k KVAuthTransitionStore) Close() {
	panic("unimplemented")
}
