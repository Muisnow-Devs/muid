package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared/kv"
)

// pendingTTL bounds how long a consent screen may stay open before the
// authorization request must be restarted.
const pendingTTL = 10 * time.Minute

const pendingKeyPrefix = "muid:oidc:authz:"

// PendingAuthorization is an Authorize request parked while the user decides
// on the consent screen.
type PendingAuthorization struct {
	ID uuid.UUID `json:"id"`

	ClientRefID uuid.UUID `json:"client_ref_id"`
	ClientID    string    `json:"client_id"`
	UserID      uuid.UUID `json:"user_id"`
	SessionID   uuid.UUID `json:"session_id"`

	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes,omitempty"`
	State       string   `json:"state,omitempty"`
	Nonce       string   `json:"nonce,omitempty"`

	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	AuthTime  int64 `json:"auth_time"`
	CreatedAt int64 `json:"created_at"`
}

// KVPendingStore stores authorizations awaiting a consent decision.
type KVPendingStore struct {
	client kv.AtomicKVStore
}

func NewKVPendingStore(client kv.AtomicKVStore) *KVPendingStore {
	return &KVPendingStore{client: client}
}

func (s *KVPendingStore) Create(
	ctx context.Context,
	pending PendingAuthorization,
) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	pending.ID = id
	pending.CreatedAt = time.Now().Unix()

	data, err := json.Marshal(pending)
	if err != nil {
		return uuid.Nil, err
	}

	ok, err := s.client.SetNX(ctx, pendingKeyPrefix+id.String(), data, pendingTTL)
	if err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, ErrConflict
	}
	return id, nil
}

// Consume atomically claims the pending authorization so a consent decision
// can only be applied once.
func (s *KVPendingStore) Consume(
	ctx context.Context,
	id uuid.UUID,
) (PendingAuthorization, error) {
	key := pendingKeyPrefix + id.String()
	data, err := s.client.Get(ctx, key)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return PendingAuthorization{}, ErrNotFound
	}
	if err != nil {
		return PendingAuthorization{}, err
	}

	claimed, err := s.client.CompareAndDelete(ctx, key, data)
	if err != nil {
		return PendingAuthorization{}, err
	}
	if !claimed {
		return PendingAuthorization{}, ErrNotFound
	}

	var pending PendingAuthorization
	err = json.Unmarshal(data, &pending)
	if err != nil {
		return PendingAuthorization{}, err
	}
	return pending, nil
}
