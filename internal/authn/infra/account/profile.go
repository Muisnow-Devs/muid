package account

import (
	"context"

	"github.com/google/uuid"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/pkg/traceid"
)

func (s *Store) provisionFromProfile(
	ctx context.Context,
	email string,
	claims *claimspb.IdentityInformation,
) (uuid.UUID, error) {
	if s.Profile == nil {
		return uuid.Nil, errProfileClientUnset
	}

	pctx, cancel := context.WithTimeout(ctx, s.profileTimeout())
	defer cancel()

	if id, ok := traceid.FromContext(ctx); ok {
		pctx = traceid.With(pctx, id)
	}

	req := &profilepb.CreateProfileRequest{}
	req.SetEmail(email)
	if claims != nil {
		req.SetIdentity(claims)
	}

	resp, err := s.Profile.CreateProfile(pctx, req)
	if err != nil {
		return uuid.Nil, err
	}

	uid, err := uuid.Parse(resp.GetId())
	if err != nil {
		return uuid.Nil, err
	}

	if err := s.DB.UserRef.Create().
		SetID(uid).
		SetEmail(email).
		Exec(ctx); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}
