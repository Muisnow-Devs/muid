package issuer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared/tracing"
)

const (
	defaultSessionLifetime  = 48 * time.Hour
	SessionAbsoluteLifetime = 90 * 24 * time.Hour
)

// parsedToken holds the decoded selector bytes and pre-computed validator hash
// derived from a wire session token.
type parsedToken struct {
	selector      []byte
	validatorHash [32]byte
}

// parseWireToken parses a wire session token string into its selector bytes and
// validator hash. All three token-handling operations (resolve, revoke, extend)
// share this step so it lives in one place.
func parseWireToken(wireToken string) (parsedToken, error) {
	selectorB64, validatorB64, err := session.ParseWireSessionToken(wireToken)
	if err != nil {
		return parsedToken{}, err
	}
	selector, err := session.DecodeWireSelectorBytes(selectorB64)
	if err != nil {
		return parsedToken{}, err
	}
	validatorSecret, err := session.DecodeWireValidatorSecret(validatorB64)
	if err != nil {
		return parsedToken{}, err
	}
	return parsedToken{
		selector:      selector,
		validatorHash: sha256.Sum256(validatorSecret),
	}, nil
}

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
	absoluteExpiry := now.Add(SessionAbsoluteLifetime)

	row, err := s.db.UserSession.Create().
		SetUserID(userID).
		SetSelector(selectorBytes).
		SetValidatorHash(sum[:]).
		SetExpiresAt(expires).
		SetAbsoluteExpiry(absoluteExpiry).
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

	tok, err := parseWireToken(wireToken)
	if err != nil {
		return ResolvedSession{}, err
	}

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
			// The selector is known to the cache but the validator hash does not match.
			// This strongly suggests token forgery or a cache-poisoning attempt.
			// Revoke the DB session identified by this selector as a precaution.
			go s.revokeBySelectorBytes(tok.selector)
			return ResolvedSession{}, session.ErrSessionNotFound
		}
	}

	ctx, dbSpan := tracing.StartSpan(ctx, "authn.session_db.lookup")
	row, err := s.lookupSession(ctx, tok.selector, tok.validatorHash, wireToken)
	dbSpan.End()
	if err != nil {
		return ResolvedSession{}, err
	}

	now := time.Now()
	if now.After(row.ExpiresAt) {
		return ResolvedSession{}, session.ErrSessionExpired
	}
	if now.After(row.AbsoluteExpiry) {
		return ResolvedSession{}, session.ErrSessionAbsoluteExpiry
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
			IssuedAt:      res.IssuedAt,
			ExpiresAt:     res.ExpiresAt,
			ValidatorHash: tok.validatorHash,
		})
	}

	return res, nil
}

func (s *EntSessionIssuer) RevokeSessionToken(ctx context.Context, wireToken string) error {
	tok, err := parseWireToken(wireToken)
	if err != nil {
		return err
	}

	// Fetch by selector only; do not include validator in the WHERE clause.
	row, err := s.db.UserSession.Query().
		Where(
			usersession.SelectorEQ(tok.selector),
			usersession.RevokedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return session.ErrSessionNotFound
	}
	if err != nil {
		return err
	}

	// Constant-time comparison — no auto-revoke on mismatch here because the
	// caller does not hold the real token and cannot trigger a DoS via selector.
	if subtle.ConstantTimeCompare(row.ValidatorHash, tok.validatorHash[:]) != 1 {
		return session.ErrSessionNotFound
	}

	err = s.db.UserSession.UpdateOneID(row.ID).
		SetRevokedAt(time.Now()).
		Exec(ctx)
	if err != nil {
		return err
	}

	if s.sessionCache != nil {
		errutil.Discard(s.sessionCache.Delete(ctx, wireToken))
	}

	return nil
}

func (s *EntSessionIssuer) ExtendSession(
	ctx context.Context,
	wireToken string,
) (*sessionpb.SessionContext, error) {
	tok, err := parseWireToken(wireToken)
	if err != nil {
		return nil, err
	}

	row, err := s.lookupSession(ctx, tok.selector, tok.validatorHash, wireToken)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if now.After(row.ExpiresAt) {
		return nil, session.ErrSessionExpired
	}
	if now.After(row.AbsoluteExpiry) {
		return nil, session.ErrSessionAbsoluteExpiry
	}

	// Clamp: do not extend past the absolute expiry.
	newExpiry := now.Add(defaultSessionLifetime)
	if newExpiry.After(row.AbsoluteExpiry) {
		newExpiry = row.AbsoluteExpiry
	}

	err = s.db.UserSession.UpdateOneID(row.ID).
		SetExpiresAt(newExpiry).
		SetLastExtendedAt(now).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	if s.sessionCache != nil {
		s.sessionCache.Set(ctx, wireToken, session.CachedSession{
			SessionID:     row.ID,
			UserID:        row.UserID,
			IssuedAt:      row.CreatedAt,
			ExpiresAt:     newExpiry,
			ValidatorHash: tok.validatorHash,
		})
	}

	stok := &sessionpb.SessionToken{}
	stok.SetValue(wireToken)

	sctx := &sessionpb.SessionContext{}
	sctx.SetSessionToken(stok)
	sctx.SetIssuedAt(timestamppb.New(row.CreatedAt.UTC()))
	sctx.SetExpiresAt(timestamppb.New(newExpiry.UTC()))

	return sctx, nil
}

// lookupSession fetches the session row for the given selector from the database,
// checks revocation, and verifies the validator hash in constant time.
// On a validator mismatch it fires a background revocation and always returns
// ErrSessionNotFound so callers cannot distinguish "not found" from "forged token".
// Expiry checks are left to the caller.
func (s *EntSessionIssuer) lookupSession(
	ctx context.Context,
	selector []byte,
	validatorHash [32]byte,
	wireToken string,
) (*ent.UserSession, error) {
	// Query by selector only — validator is never sent to the database.
	row, err := s.db.UserSession.Query().
		Where(usersession.SelectorEQ(selector)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	if !row.RevokedAt.IsZero() {
		return nil, session.ErrSessionNotFound
	}

	// Constant-time comparison prevents timing-based oracle attacks.
	if subtle.ConstantTimeCompare(row.ValidatorHash, validatorHash[:]) != 1 {
		// Selector found but validator is wrong — possible stolen selector or
		// brute-force attempt. Revoke the real session immediately.
		go s.revokeByID(row.ID, wireToken)
		return nil, session.ErrSessionNotFound
	}

	return row, nil
}

// revokeByID revokes a session by its primary key using a detached context.
// This is a best-effort protective action triggered by a validator mismatch;
// errors are discarded because the revocation itself is the security response.
func (s *EntSessionIssuer) revokeByID(sessionID uuid.UUID, wireToken string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.db.UserSession.UpdateOneID(sessionID).
		SetRevokedAt(time.Now()).
		Exec(ctx)
	if err == nil && s.sessionCache != nil {
		errutil.Discard(s.sessionCache.Delete(ctx, wireToken))
	}
}

// revokeBySelectorBytes revokes any active session matching the given selector
// bytes using a detached context. Used when a cache-rejection signals a
// possible token forgery or cache-poisoning attempt.
func (s *EntSessionIssuer) revokeBySelectorBytes(selector []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errutil.Discard(s.db.UserSession.Update().
		Where(
			usersession.SelectorEQ(selector),
			usersession.RevokedAtIsNil(),
		).
		SetRevokedAt(time.Now()).
		Exec(ctx))
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
