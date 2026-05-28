package issuer

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
	"sanzi.io/muid/pkg/shared/tracing"
)

const defaultSessionLifetime = 48 * time.Hour

type EntSessionIssuer struct {
	db           *ent.Client
	sessionCache session.SessionCache
}

func NewEntSessionIssuer(db *ent.Client, sessionCache session.SessionCache) SessionIssuer {
	return &EntSessionIssuer{
		db:           db,
		sessionCache: sessionCache,
	}
}

func (s *EntSessionIssuer) CreateSession(
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

	row, err := s.db.UserSession.Create().
		SetUserID(userID).
		SetSelector(selectorBytes).
		SetValidatorHash(sum[:]).
		SetExpiresAt(expires).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	// Update last login
	err = s.db.UserRef.UpdateOneID(userID).SetLastLoginAt(now).Exec(ctx)
	if err != nil {
		return nil, err
	}

	if s.sessionCache != nil {
		s.sessionCache.Set(ctx, wireToken, session.CachedSession{
			SessionID:     row.ID,
			UserID:        userID,
			ValidatorHash: sum,
			IssuedAt:      now,
			ExpiresAt:     expires,
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

func (s *EntSessionIssuer) ResolveSessionToken(
	ctx context.Context,
	wireToken string,
) (ResolvedSession, error) {
	ctx, span := tracing.StartSpan(ctx, "authn.resolve_session")
	defer span.End()

	selectorB64, validatorB64, err := session.ParseWireSessionToken(wireToken)
	if err != nil {
		return ResolvedSession{}, err
	}

	validatorSecret, err := session.DecodeWireValidatorSecret(validatorB64)
	if err != nil {
		return ResolvedSession{}, err
	}
	validatorHash := sha256.Sum256(validatorSecret)

	if s.sessionCache != nil {
		ctx, cacheSpan := tracing.StartSpan(ctx, "authn.session_cache.get")
		cached, cacheErr := s.sessionCache.Get(ctx, wireToken)
		cacheSpan.End()
		if cacheErr == nil {
			return ResolvedSession{
				SessionID: cached.SessionID,
				UserID:    cached.UserID,
				ExpiresAt: cached.ExpiresAt,
				IssuedAt:  cached.IssuedAt,
			}, nil
		}

		if errors.Is(cacheErr, session.ErrSessionCacheRejected) {
			return ResolvedSession{}, session.ErrSessionNotFound
		}
	}

	selector, err := session.DecodeWireSelectorBytes(selectorB64)
	if err != nil {
		return ResolvedSession{}, err
	}
	sum := validatorHash

	ctx, dbSpan := tracing.StartSpan(ctx, "authn.session_db.lookup")
	row, err := s.db.UserSession.Query().
		Where(
			usersession.SelectorEQ(selector),
			usersession.ValidatorHashEQ(sum[:]),
		).
		Only(ctx)
	dbSpan.End()
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

	if s.sessionCache != nil {
		s.sessionCache.Set(ctx, wireToken, session.CachedSession{
			SessionID:     res.SessionID,
			UserID:        res.UserID,
			ExpiresAt:     res.ExpiresAt,
			ValidatorHash: sum,
		})
	}

	return res, nil
}

func (s *EntSessionIssuer) RevokeSessionToken(ctx context.Context, wireToken string) error {
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
	n, err := s.db.UserSession.Update().
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

	if s.sessionCache != nil {
		s.sessionCache.Delete(ctx, wireToken)
	}

	return nil
}

func (s *EntSessionIssuer) SessionCreatedAt(
	ctx context.Context,
	sessionID uuid.UUID,
) (time.Time, error) {
	row, err := s.db.UserSession.Get(ctx, sessionID)
	if ent.IsNotFound(err) {
		return time.Time{}, session.ErrSessionNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	return row.CreatedAt, nil
}

func (s *EntSessionIssuer) AuthenticatedResultFromResolved(
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

func (s *EntSessionIssuer) AuthenticatedPrincipalFromResolved(
	resolved ResolvedSession,
) *sessionpb.AuthenticatedPrincipal {
	out := &sessionpb.AuthenticatedPrincipal{}
	out.SetUserId(resolved.UserID.String())
	out.SetAuthLevel(sessionpb.AuthLevel_AUTH_LEVEL_MEDIUM)
	out.SetIssuedAt(timestamppb.New(resolved.IssuedAt.UTC()))
	out.SetExpiresAt(timestamppb.New(resolved.ExpiresAt.UTC()))
	return out
}
