package resolver

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userref"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/tracing"
)

type EntUserResolver struct {
	db                 *ent.Client
	profileCli         profilepb.ProfileServiceClient
	profileCallTimeout time.Duration
}

func NewEntUserResolver(
	db *ent.Client,
	profileCli profilepb.ProfileServiceClient,
	profileCallTimeout time.Duration,
) UserResolver {
	if profileCallTimeout <= 0 {
		profileCallTimeout = 10 * time.Second
	}
	return &EntUserResolver{
		db:                 db,
		profileCli:         profileCli,
		profileCallTimeout: profileCallTimeout,
	}
}

func (r *EntUserResolver) ResolveUser(
	ctx context.Context,
	identity *claims.IdentityInformation,
) (UserResolution, error) {
	if identity == nil {
		return UserResolution{}, errors.New("resolver: missing identity claims")
	}

	email := strings.TrimSpace(strings.ToLower(identity.GetEmail()))
	if email == "" {
		return UserResolution{}, errors.New("resolver: missing email claim")
	}

	// 1. Lookup in UserRef table
	ref, err := r.db.UserRef.Query().Where(userref.EmailEQ(email)).Only(ctx)
	if err == nil {
		return UserResolution{
			UserID:   ref.ID,
			Created:  false,
			Existing: true,
		}, nil
	}
	if !ent.IsNotFound(err) {
		return UserResolution{}, err
	}

	// 2. Not found, create user
	var uid uuid.UUID
	if r.profileCli != nil {
		pctx, cancel := context.WithTimeout(ctx, r.profileCallTimeout)
		defer cancel()

		if logID, ok := log.FromContext(ctx); ok {
			pctx = log.With(pctx, logID)
		}

		req := &profilepb.CreateProfileRequest{}
		req.SetEmail(email)
		req.SetIdentity(identity)

		pctx, span := tracing.StartSpan(pctx, "authn.profile.create_profile")
		resp, err := r.profileCli.CreateProfile(pctx, req)
		span.End()
		if err != nil {
			return UserResolution{}, err
		}

		parsed, err := uuid.Parse(resp.GetId())
		if err != nil {
			return UserResolution{}, err
		}
		uid = parsed
	} else {
		return UserResolution{}, errors.New("resolver: profile client not configured")
	}

	// Insert UserRef record
	err = r.db.UserRef.Create().
		SetID(uid).
		SetEmail(email).
		Exec(ctx)
	if err != nil {
		return UserResolution{}, err
	}

	return UserResolution{
		UserID:   uid,
		Created:  true,
		Existing: false,
	}, nil
}
