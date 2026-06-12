package profilegrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/profile/v1"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
)

func (g *GRPCHandler) StartAvatarUpload(
	ctx context.Context,
	req *pb.StartAvatarUploadRequest,
) (*pb.StartAvatarUploadResponse, error) {
	userID, err := sharedauthn.RequiredAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	sess, err := g.mgr.StartAvatarUpload(ctx, userID, req.GetContentType())
	if err != nil {
		return nil, mapAvatarError(ctx, "avatar start", err)
	}

	resp := &pb.StartAvatarUploadResponse{}
	resp.SetUploadUrl(sess.UploadURL)
	resp.SetObjectKey(sess.ObjectKey)
	resp.SetExpiresAt(timestamppb.New(sess.ExpiresAt))
	return resp, nil
}

func (g *GRPCHandler) CompleteAvatarUpload(
	ctx context.Context,
	req *pb.CompleteAvatarUploadRequest,
) (*pb.CompleteAvatarUploadResponse, error) {
	userID, err := sharedauthn.RequiredAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	avatarURL, err := g.mgr.CompleteAvatarUpload(
		ctx,
		userID,
		req.GetObjectKey(),
		req.GetByteSize(),
	)
	if err != nil {
		return nil, mapAvatarError(ctx, "avatar complete", err)
	}

	resp := &pb.CompleteAvatarUploadResponse{}
	resp.SetAvatarUrl(avatarURL)
	return resp, nil
}
