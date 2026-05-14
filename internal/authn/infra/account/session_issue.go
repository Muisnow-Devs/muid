package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
)

// IssueAuthenticatedSession creates a [ent.UserSession] row and returns wire-safe session material.
func (s *Services) IssueAuthenticatedSession(
	ctx context.Context,
	userID uuid.UUID,
) (*sessionpb.AuthenticatedResult, error) {
	selectorBytes := make([]byte, 16)
	if _, err := rand.Read(selectorBytes); err != nil {
		return nil, err
	}
	validatorSecret := make([]byte, 32)
	if _, err := rand.Read(validatorSecret); err != nil {
		return nil, err
	}

	selector := base64.RawURLEncoding.EncodeToString(selectorBytes)
	validatorEncoded := base64.RawURLEncoding.EncodeToString(validatorSecret)
	wireToken := selector + "." + validatorEncoded

	if len(selector) != 22 || len(validatorEncoded) != 43 {
		return nil, fmt.Errorf(
			"session token segments unexpected lengths %d/%d",
			len(selector),
			len(validatorEncoded),
		)
	}

	sum := sha256.Sum256(validatorSecret)
	now := time.Now()
	expires := now.Add(7 * 24 * time.Hour)

	if err := s.DB.UserSession.Create().
		SetUserID(userID).
		SetSelector(selectorBytes[:]).
		SetValidatorHash(sum[:]).
		SetExpiresAt(expires).
		Exec(ctx); err != nil {
		return nil, err
	}

	if err := s.touchLastLogin(ctx, userID); err != nil {
		return nil, err
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
