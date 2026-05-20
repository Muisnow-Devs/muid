package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/usersession"
	"sanzi.io/muid/internal/session"
)

type sessionService struct {
	store *Store
}

// ResolvedSession is a validated, non-revoked user session.
type ResolvedSession struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	IssuedAt  time.Time
}

const defaultSessionLifetime = 7 * 24 * time.Hour

// IssueAuthenticatedSession creates a [ent.UserSession] row and returns wire-safe session material.
func (s *sessionService) IssueAuthenticatedSession(
	ctx context.Context,
	userID uuid.UUID,
) (*sessionpb.AuthenticatedResult, error) {
	selectorBytes := make([]byte, 16)
	_, err := rand.Read(selectorBytes)
	if err != nil {
		return nil, err
	}

	validatorSecret := make([]byte, 32)
	_, err = rand.Read(validatorSecret)
	if err != nil {
		return nil, err
	}

	selectorB64 := base64.RawURLEncoding.EncodeToString(selectorBytes)
	validatorEncoded := base64.RawURLEncoding.EncodeToString(validatorSecret)
	wireToken := selectorB64 + "." + validatorEncoded

	if len(selectorB64) != 22 || len(validatorEncoded) != 43 {
		return nil, fmt.Errorf(
			"session token segments unexpected lengths %d/%d",
			len(selectorB64),
			len(validatorEncoded),
		)
	}

	sum := sha256.Sum256(validatorSecret)
	now := time.Now()
	expires := now.Add(defaultSessionLifetime)

	row, err := s.store.DB.UserSession.Create().
		SetUserID(userID).
		SetSelector(selectorBytes).
		SetValidatorHash(sum[:]).
		SetExpiresAt(expires).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	err = s.store.touchLastLogin(ctx, userID)
	if err != nil {
		return nil, err
	}

	if s.store.SessionCache != nil {
		s.store.SessionCache.Set(ctx, wireToken, session.CachedSession{
			SessionID:     row.ID,
			UserID:        userID,
			ExpiresAt:     expires,
			ValidatorHash: sum,
		})
	}

	stok := &sessionpb.SessionToken{}
	stok.SetValue(wireToken)

	sctx := &sessionpb.SessionContext{}
	sctx.SetSessionToken(stok)
	sctx.SetIssuedAt(timestamppb.New(now))
	sctx.SetExpiresAt(timestamppb.New(expires))

	out := &sessionpb.AuthenticatedResult{}
	out.SetUserId(userID.String())
	out.SetSessionContext(sctx)
	out.SetAuthLevel(sessionpb.AuthLevel_AUTH_LEVEL_MEDIUM)

	return out, nil
}

// ResolveSessionToken validates a wire session token (validated Redis cache, then database).
func (s *sessionService) ResolveSessionToken(
	ctx context.Context,
	wireToken string,
) (ResolvedSession, error) {
	selectorB64, validatorB64, err := session.ParseWireSessionToken(wireToken)
	if err != nil {
		return ResolvedSession{}, err
	}

	validatorSecret, err := session.DecodeWireValidatorSecret(validatorB64)
	if err != nil {
		return ResolvedSession{}, err
	}
	validatorHash := sha256.Sum256(validatorSecret)

	if s.store.SessionCache != nil {
		cached, cacheErr := s.store.SessionCache.Get(ctx, wireToken)
		if cacheErr == nil {
			return ResolvedSession{
				SessionID: cached.SessionID,
				UserID:    cached.UserID,
				ExpiresAt: cached.ExpiresAt,
				IssuedAt:  cached.ExpiresAt.Add(-defaultSessionLifetime),
			}, nil
		}

		if errors.Is(cacheErr, session.ErrSessionCacheRejected) {
			return ResolvedSession{}, session.ErrSessionNotFound
		}

		if !errorsIsSessionMiss(cacheErr) {
			return ResolvedSession{}, cacheErr
		}
	}

	selector, err := session.DecodeWireSelectorBytes(selectorB64)
	if err != nil {
		return ResolvedSession{}, err
	}
	sum := validatorHash

	row, err := s.store.DB.UserSession.Query().
		Where(
			usersession.SelectorEQ(selector),
			usersession.ValidatorHashEQ(sum[:]),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return ResolvedSession{}, session.ErrSessionNotFound
	}
	if err != nil {
		return ResolvedSession{}, err
	}
	if !row.RevokedAt.IsZero() {
		return ResolvedSession{}, session.ErrSessionNotFound
	}
	if time.Now().After(row.ExpiresAt) {
		return ResolvedSession{}, session.ErrSessionExpired
	}

	res := ResolvedSession{
		SessionID: row.ID,
		UserID:    row.UserID,
		ExpiresAt: row.ExpiresAt,
		IssuedAt:  row.CreatedAt,
	}
	if s.store.SessionCache != nil {
		s.store.SessionCache.Set(ctx, wireToken, session.CachedSession{
			SessionID:     res.SessionID,
			UserID:        res.UserID,
			ExpiresAt:     res.ExpiresAt,
			ValidatorHash: sum,
		})
	}
	return res, nil
}

// RevokeSessionToken revokes the session and drops any cache entry.
func (s *sessionService) RevokeSessionToken(ctx context.Context, wireToken string) error {
	selectorB64, validatorB64, err := session.ParseWireSessionToken(wireToken)
	if err != nil {
		return err
	}

	selector, err := session.DecodeWireSelectorBytes(selectorB64)
	if err != nil {
		return err
	}

	validatorSecret, err := session.DecodeWireValidatorSecret(validatorB64)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(validatorSecret)

	now := time.Now()
	n, err := s.store.DB.UserSession.Update().
		Where(
			usersession.SelectorEQ(selector),
			usersession.ValidatorHashEQ(sum[:]),
			usersession.RevokedAtIsNil(),
		).
		SetRevokedAt(now).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return session.ErrSessionNotFound
	}

	if s.store.SessionCache != nil {
		s.store.SessionCache.Delete(ctx, wireToken)
	}

	return nil
}

// AuthenticatedResultFromResolved rebuilds wire session material for an existing token.
func (s *sessionService) AuthenticatedResultFromResolved(
	wireToken string,
	resolved ResolvedSession,
) *sessionpb.AuthenticatedResult {
	stok := &sessionpb.SessionToken{}
	stok.SetValue(wireToken)

	sctx := &sessionpb.SessionContext{}
	sctx.SetSessionToken(stok)
	sctx.SetIssuedAt(timestamppb.New(resolved.IssuedAt.UTC()))
	sctx.SetExpiresAt(timestamppb.New(resolved.ExpiresAt.UTC()))

	out := &sessionpb.AuthenticatedResult{}
	out.SetUserId(resolved.UserID.String())
	out.SetSessionContext(sctx)
	out.SetAuthLevel(sessionpb.AuthLevel_AUTH_LEVEL_MEDIUM)

	return out
}

func errorsIsSessionMiss(err error) bool {
	return errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired)
}
