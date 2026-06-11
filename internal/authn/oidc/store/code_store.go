package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared/kv"
	"sanzi.io/muid/pkg/shared/tracing"
)

// codeTTL keeps authorization codes single-use and short-lived per RFC 6749
// §4.1.2 ("A maximum authorization code lifetime of 10 minutes is
// RECOMMENDED"); we are deliberately stricter.
const codeTTL = 60 * time.Second

const codeKeyPrefix = "muid:oidc:code:"

// CodeRecord is the state bound to one authorization code.
type CodeRecord struct {
	ClientRefID uuid.UUID `json:"client_ref_id"`
	ClientID    string    `json:"client_id"`
	UserID      uuid.UUID `json:"user_id"`
	SessionID   uuid.UUID `json:"session_id"`

	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes,omitempty"`
	Nonce       string   `json:"nonce,omitempty"`

	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	AuthTime int64 `json:"auth_time"`
	IssuedAt int64 `json:"issued_at"`
}

// KVCodeStore stores authorization codes with single-use consumption.
type KVCodeStore struct {
	client kv.AtomicKVStore
}

func NewKVCodeStore(client kv.AtomicKVStore) *KVCodeStore {
	return &KVCodeStore{client: client}
}

// Create mints a fresh authorization code for record.
func (s *KVCodeStore) Create(ctx context.Context, record CodeRecord) (string, error) {
	code, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	record.IssuedAt = time.Now().Unix()

	data, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	ok, err := s.client.SetNX(ctx, codeKeyPrefix+code, data, codeTTL)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrConflict
	}
	return code, nil
}

// Consume atomically claims the code: concurrent consumers see ErrNotFound,
// making replayed codes fail with invalid_grant.
func (s *KVCodeStore) Consume(ctx context.Context, code string) (CodeRecord, error) {
	ctx, span := tracing.StartSpan(ctx, "authn.oidc.code.consume")
	defer span.End()

	key := codeKeyPrefix + code
	data, err := s.client.Get(ctx, key)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return CodeRecord{}, ErrNotFound
	}
	if err != nil {
		return CodeRecord{}, err
	}

	claimed, err := s.client.CompareAndDelete(ctx, key, data)
	if err != nil {
		return CodeRecord{}, err
	}
	if !claimed {
		return CodeRecord{}, ErrNotFound
	}

	var record CodeRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return CodeRecord{}, err
	}
	return record, nil
}
