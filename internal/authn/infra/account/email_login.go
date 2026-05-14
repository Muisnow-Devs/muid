package account

import (
	"context"

	"github.com/google/uuid"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userref"
	"sanzi.io/muid/pkg/traceid"
)

// ResolveEmailLogin returns the authn user id for the email address, creating profile + UserRef when absent.
func (s *Services) ResolveEmailLogin(ctx context.Context, email string) (uuid.UUID, error) {
	ref, err := s.DB.UserRef.Query().Where(userref.EmailEQ(email)).Only(ctx)
	if ent.IsNotFound(err) {
		return s.provisionFromProfile(ctx, email, nil)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return ref.ID, nil
}

func (s *Services) provisionFromProfile(
	ctx context.Context,
	email string,
	claims *claimspb.IdentityClaims,
) (uuid.UUID, error) {
	if s.Profile == nil {
		return uuid.Nil, errProfileClientUnset
	}
	pctx, cancel := context.WithTimeout(ctx, s.profileTimeout())
	defer cancel()
	if id, ok := traceid.FromContext(ctx); ok {
		pctx = traceid.With(pctx, id)
	}
	req := &profilepb.CreateProfileRequest{Email: email}
	if claims != nil {
		req.Claims = claims
	}
	resp, err := s.Profile.CreateProfile(pctx, req)
	if err != nil {
		return uuid.Nil, err
	}
	uid, err := uuid.Parse(resp.GetId())
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.DB.UserRef.Create().SetID(uid).SetEmail(email).Exec(ctx); err != nil {
		return uuid.Nil, err
	}
	return uid, nil
}
