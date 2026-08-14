package profilegrpc

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/profile/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
)

// ProfileRequestContextInterceptor validates request user/profile ids and attaches log attrs.
func ProfileRequestContextInterceptor() grpc.UnaryServerInterceptor {
	return grpcutils.UnaryRequestContextInterceptor(map[string]grpcutils.RequestContextFunc{
		pb.ProfileService_GetProfile_FullMethodName:           enrichGetProfile,
		pb.ProfileService_UpdateProfile_FullMethodName:        enrichRequiredPrincipal,
		pb.ProfileService_StartAvatarUpload_FullMethodName:    enrichRequiredPrincipal,
		pb.ProfileService_CompleteAvatarUpload_FullMethodName: enrichRequiredPrincipal,
		// CreateOrganizationProfile is service-to-service (authz) and carries
		// no principal, mirroring CreateProfile; only the user-facing RPCs
		// require an authenticated caller.
		pb.OrganizationProfileService_GetOrganizationProfile_FullMethodName:    enrichRequiredUser,
		pb.OrganizationProfileService_UpdateOrganizationProfile_FullMethodName: enrichRequiredUser,
	})
}

func enrichRequiredPrincipal(ctx context.Context, _ string, _ any) (context.Context, error) {
	ctx, id, err := sharedauthn.EnrichRequiredAuthenticatedUser(ctx)
	if err != nil {
		return ctx, err
	}
	return log.WithAttrs(ctx, log.ProfileID(id)), nil
}

// enrichRequiredUser requires a verified authenticated caller without treating
// the id as a profile id; used by organization-profile RPCs where the caller is
// acting on an organization, not their own profile.
func enrichRequiredUser(ctx context.Context, _ string, _ any) (context.Context, error) {
	ctx, _, err := sharedauthn.EnrichRequiredAuthenticatedUser(ctx)
	return ctx, err
}

func enrichGetProfile(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.GetProfileRequest)
	if !ok {
		log.LogUnexpected(ctx, "enrich get profile", "invalid request type")
		return ctx, status.Errorf(codes.Internal, "internal error")
	}
	return enrichProfileUserID(ctx, r.GetId(), "invalid profile id")
}

func enrichProfileUserID(ctx context.Context, raw, invalidMsg string) (context.Context, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		ctx, id, err := sharedauthn.EnrichRequiredAuthenticatedUser(ctx)
		if err != nil {
			return ctx, err
		}
		return log.WithAttrs(ctx, log.ProfileID(id)), nil
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		return ctx, status.Error(codes.InvalidArgument, invalidMsg)
	}

	return log.WithAttrs(ctx, log.ProfileID(id)), nil
}
