package profilegrpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/profile/core"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
)

func (g *GRPCHandler) CreateProfile(
	ctx context.Context,
	req *pb.CreateProfileRequest,
) (*pb.CreateProfileResponse, error) {
	id, err := g.mgr.CreateProfile(ctx, req.GetIdentity())
	if err != nil {
		return nil, mapProfileError(ctx, "profile create", err)
	}

	resp := &pb.CreateProfileResponse{}
	resp.SetId(id.String())
	return resp, nil
}

func (g *GRPCHandler) GetProfile(
	ctx context.Context,
	req *pb.GetProfileRequest,
) (*pb.GetProfileResponse, error) {
	id, err := sharedauthn.RequiredAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	p, err := g.mgr.GetProfile(ctx, id)
	if errors.Is(err, core.ErrProfileNotFound) {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	if err != nil {
		return nil, mapProfileError(ctx, "profile get", err)
	}

	resp := &pb.GetProfileResponse{}
	resp.SetId(p.ID.String())
	resp.SetDisplayName(p.DisplayName)
	resp.SetUsername(p.Username)
	resp.SetAvatarUrl(p.AvatarURL)
	resp.SetLocale(p.Locale)
	resp.SetTimezone(p.Timezone)
	resp.SetBio(p.Bio)
	resp.SetAvatarObjectKey(p.AvatarObjectKey)

	if p.OriginalIdentity != nil {
		resp.SetOriginalIdentity(*p.OriginalIdentity)
	}

	return resp, nil
}

func (g *GRPCHandler) UpdateProfile(
	ctx context.Context,
	req *pb.UpdateProfileRequest,
) (*pb.UpdateProfileResponse, error) {
	id, err := sharedauthn.RequiredAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	err = g.mgr.UpdateProfile(ctx, id, req.GetUpdateMask(), req.GetIdentity())
	if errors.Is(err, core.ErrProfileNotFound) {
		return nil, status.Error(codes.NotFound, "requested resource not found")
	}
	if err != nil {
		return nil, mapProfileError(ctx, "profile update", err)
	}

	resp := &pb.UpdateProfileResponse{}
	resp.SetId(id.String())
	return resp, nil
}
