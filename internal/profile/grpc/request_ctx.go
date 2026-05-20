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
)

type profileUserIDKey struct{}

// ProfileUserIDFromContext returns the profile user id attached by [ProfileRequestContextInterceptor].
func ProfileUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	if ctx == nil {
		return uuid.Nil, false
	}
	id, ok := ctx.Value(profileUserIDKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// ProfileRequestContextInterceptor validates request user/profile ids and attaches log attrs.
func ProfileRequestContextInterceptor() grpc.UnaryServerInterceptor {
	return grpcutils.UnaryRequestContextInterceptor(map[string]grpcutils.RequestContextFunc{
		pb.ProfileService_GetProfile_FullMethodName:           enrichGetProfile,
		pb.ProfileService_UpdateProfile_FullMethodName:        enrichUpdateProfile,
		pb.ProfileService_StartAvatarUpload_FullMethodName:    enrichStartAvatarUpload,
		pb.ProfileService_CompleteAvatarUpload_FullMethodName: enrichCompleteAvatarUpload,
	})
}

func enrichGetProfile(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.GetProfileRequest)
	if !ok {
		return ctx, status.Errorf(codes.Internal, "unsupported request type")
	}
	return enrichProfileUserID(ctx, r.GetId(), "invalid profile id")
}

func enrichUpdateProfile(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.UpdateProfileRequest)
	if !ok {
		return ctx, status.Errorf(codes.Internal, "unsupported request type")
	}
	return enrichProfileUserID(ctx, r.GetId(), "invalid profile id")
}

func enrichStartAvatarUpload(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.StartAvatarUploadRequest)
	if !ok {
		return ctx, status.Errorf(codes.Internal, "unsupported request type")
	}
	return enrichProfileUserID(ctx, r.GetUserId(), msgInvalidUserID)
}

func enrichCompleteAvatarUpload(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.CompleteAvatarUploadRequest)
	if !ok {
		return ctx, status.Errorf(codes.Internal, "unsupported request type")
	}
	return enrichProfileUserID(ctx, r.GetUserId(), msgInvalidUserID)
}

func enrichProfileUserID(ctx context.Context, raw, invalidMsg string) (context.Context, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ctx, status.Error(codes.InvalidArgument, invalidMsg)
	}
	ctx = log.WithAttrs(ctx, log.UserIDPrefix(id.String()))
	ctx = context.WithValue(ctx, profileUserIDKey{}, id)
	return ctx, nil
}

func requiredProfileUserID(ctx context.Context) (uuid.UUID, error) {
	id, ok := ProfileUserIDFromContext(ctx)
	if !ok {
		return uuid.Nil, status.Error(codes.Internal, "missing profile user id in context")
	}
	return id, nil
}
