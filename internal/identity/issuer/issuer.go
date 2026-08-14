package issuer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useremail"
	"sanzi.io/muid/internal/authn/ent/usersession"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/log"
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

// primaryEmail returns the primary active email address for the given user.
// It is best-effort: errors are silently ignored and an empty string is returned.
func (s *EntSessionIssuer) primaryEmail(ctx context.Context, userID uuid.UUID) string {
	ue, err := s.db.UserEmail.Query().
		Where(
			useremail.UserIDEQ(userID),
			useremail.IsPrimaryEQ(true),
			useremail.RevokedAtIsNil(),
		).
		Only(ctx)
	if err != nil {
		return ""
	}
	return ue.Email
}

func (s *EntSessionIssuer) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	metadata session.SessionMetadata,
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
		SetDeviceName(metadata.Device).
		SetIPAddress(metadata.IPAddress).
		SetUserAgent(metadata.UserAgent).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	// Update last login timestamp.
	err = s.db.UserRef.UpdateOneID(userID).SetLastLoginAt(now).Exec(ctx)
	if err != nil {
		return nil, err
	}

	// Best-effort: fetch the primary email for the session cache.
	email := s.primaryEmail(ctx, userID)

	if s.sessionCache != nil {
		s.sessionCache.Set(ctx, selectorB64, session.CachedSession{
			SessionID:     row.ID,
			UserID:        userID,
			Email:         email,
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

	res, err := s.lookupSession(ctx, wireToken)
	if err != nil {
		return ResolvedSession{}, err
	}

	now := time.Now()
	if now.After(res.ExpiresAt) {
		return ResolvedSession{}, session.ErrSessionExpired
	}
	if now.After(res.AbsoluteExpiry) {
		return ResolvedSession{}, session.ErrSessionAbsoluteExpiry
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
		selectorB64 := base64.RawURLEncoding.EncodeToString(tok.selector)
		errutil.Discard(s.sessionCache.Delete(ctx, selectorB64))
	}

	return nil
}

func (s *EntSessionIssuer) RefreshSession(
	ctx context.Context,
	wireToken string,
) (*sessionpb.SessionContext, error) {
	res, err := s.lookupSession(ctx, wireToken)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if now.After(res.ExpiresAt) {
		return nil, session.ErrSessionExpired
	}
	if now.After(res.AbsoluteExpiry) {
		return nil, session.ErrSessionAbsoluteExpiry
	}

	// Clamp: do not extend past the absolute expiry.
	newExpiry := now.Add(defaultSessionLifetime)
	if newExpiry.After(res.AbsoluteExpiry) {
		newExpiry = res.AbsoluteExpiry
	}

	err = s.db.UserSession.UpdateOneID(res.SessionID).
		SetExpiresAt(newExpiry).
		SetLastExtendedAt(now).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	// Best-effort: refresh primary email in the cache on extension.
	if s.sessionCache != nil {
		tok, err := parseWireToken(wireToken)
		if err == nil {
			selectorB64 := base64.RawURLEncoding.EncodeToString(tok.selector)
			s.sessionCache.Set(ctx, selectorB64, session.CachedSession{
				SessionID:      res.SessionID,
				UserID:         res.UserID,
				Email:          res.Email,
				IssuedAt:       res.IssuedAt,
				ExpiresAt:      newExpiry,
				AbsoluteExpiry: res.AbsoluteExpiry,
				ValidatorHash:  tok.validatorHash,
			})
		}
	}

	stok := &sessionpb.SessionToken{}
	stok.SetValue(wireToken)

	sctx := &sessionpb.SessionContext{}
	sctx.SetSessionToken(stok)
	sctx.SetIssuedAt(timestamppb.New(res.IssuedAt.UTC()))
	sctx.SetExpiresAt(timestamppb.New(newExpiry.UTC()))

	return sctx, nil
}

type internalSession struct {
	SessionID      uuid.UUID
	UserID         uuid.UUID
	Email          string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	AbsoluteExpiry time.Time
	ValidatorHash  [32]byte
}

// lookupSession resolves a session token from either the cache or the database.
// It verifies the validator hash in constant-time.
func (s *EntSessionIssuer) lookupSession(
	ctx context.Context,
	wireToken string,
) (ResolvedSession, error) {
	tok, err := parseWireToken(wireToken)
	if err != nil {
		return ResolvedSession{}, err
	}

	// cache lookup
	cached, cacheHit := s.getCachedSession(ctx, tok.selector)

	var res internalSession
	if cacheHit {
		// cache miss
		ctx, dbSpan := tracing.StartSpan(ctx, "authn.session_db.lookup")
		row, err := s.db.UserSession.Query().
			Where(usersession.SelectorEQ(tok.selector)).
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

		res = fromDB(row)
		s.populateCache(ctx, tok.selector, res)
	} else {
		res = fromCache(cached)
	}

	// Constant-time validator verification
	if subtle.ConstantTimeCompare(res.ValidatorHash[:], tok.validatorHash[:]) != 1 {
		return ResolvedSession{}, session.ErrSessionNotFound
	}

	result := ResolvedSession{
		SessionID:      res.SessionID,
		UserID:         res.UserID,
		Email:          res.Email,
		IssuedAt:       res.IssuedAt,
		ExpiresAt:      res.ExpiresAt,
		AbsoluteExpiry: res.AbsoluteExpiry,
	}

	return result, nil
}

func (s *EntSessionIssuer) getCachedSession(
	ctx context.Context,
	selector []byte,
) (*session.CachedSession, bool) {
	if s.sessionCache == nil {
		return nil, false
	}

	selectorB64 := base64.RawURLEncoding.EncodeToString(selector[:])

	cached, ok, err := s.sessionCache.Get(ctx, selectorB64)
	if err != nil {
		log.LogUnexpected(ctx, "session cache get", err.Error())
		return nil, false
	}

	return &cached, ok
}

func fromDB(row *ent.UserSession) internalSession {
	return internalSession{
		SessionID:      row.ID,
		UserID:         row.UserID,
		IssuedAt:       row.CreatedAt,
		ExpiresAt:      row.ExpiresAt,
		AbsoluteExpiry: row.AbsoluteExpiry,
		ValidatorHash:  [32]byte(row.ValidatorHash),
	}
}

func fromCache(c *session.CachedSession) internalSession {
	return internalSession{
		SessionID:      c.SessionID,
		UserID:         c.UserID,
		Email:          c.Email,
		IssuedAt:       c.IssuedAt,
		ExpiresAt:      c.ExpiresAt,
		AbsoluteExpiry: c.AbsoluteExpiry,
		ValidatorHash:  c.ValidatorHash,
	}
}

func (s *EntSessionIssuer) populateCache(
	ctx context.Context,
	selector []byte,
	sess internalSession,
) {
	email := s.primaryEmail(ctx, sess.UserID)

	// Populate cache
	if s.sessionCache != nil {
		selectorB64 := base64.RawURLEncoding.EncodeToString(selector)
		s.sessionCache.Set(ctx, selectorB64, session.CachedSession{
			SessionID:      sess.SessionID,
			UserID:         sess.UserID,
			Email:          email,
			IssuedAt:       sess.IssuedAt,
			ExpiresAt:      sess.ExpiresAt,
			AbsoluteExpiry: sess.AbsoluteExpiry,
			ValidatorHash:  sess.ValidatorHash,
		})
	}
}
