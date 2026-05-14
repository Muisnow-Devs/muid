package profilegrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/useravatar"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/pkg/shared/storage"
	"sanzi.io/muid/pkg/traceid"
)

func (g *GRPCHandler) StartAvatarUpload(ctx context.Context, req *pb.StartAvatarUploadRequest) (*pb.StartAvatarUploadResponse, error) {
	if g.avatars == nil {
		return nil, status.Error(codes.FailedPrecondition, "avatar uploads are not configured (set PROFILE_R2_* variables)")
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	if _, err := g.db.UserProfile.Get(ctx, userID); ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "profile not found")
	} else if err != nil {
		return nil, grpcInternal(ctx, "avatar start profile lookup", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	ct := strings.TrimSpace(req.GetContentType())
	if !media.AllowedRasterContentType(ct) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported content type %q (use image/jpeg, image/png, image/gif, or image/webp)", ct)
	}

	objectKey := fmt.Sprintf("avatars/%s/%s", userID.String(), uuid.NewString())
	exp := 15 * time.Minute
	url, expTime, err := g.avatars.Store.PresignPut(ctx, g.avatars.UploadBucket, objectKey, ct, exp)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar presign put", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	_, err = g.db.UserAvatar.Update().
		Where(useravatar.HasUserWith(userprofile.ID(userID))).
		SetObjectKey(objectKey).
		SetContentType(ct).
		ClearUploadedAt().
		SetByteSize(0).
		Save(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar start record pending", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	return &pb.StartAvatarUploadResponse{
		UploadUrl:     url,
		ObjectKey:     objectKey,
		ExpiresAtUnix: expTime.Unix(),
	}, nil
}

func (g *GRPCHandler) CompleteAvatarUpload(ctx context.Context, req *pb.CompleteAvatarUploadRequest) (*pb.CompleteAvatarUploadResponse, error) {
	if g.avatars == nil {
		return nil, status.Error(codes.FailedPrecondition, "avatar uploads are not configured (set PROFILE_R2_* variables)")
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	if !strings.HasPrefix(req.GetObjectKey(), "avatars/"+userID.String()+"/") {
		return nil, status.Error(codes.InvalidArgument, "object_key does not belong to this user")
	}

	av, err := g.db.UserAvatar.Query().
		Where(useravatar.HasUserWith(userprofile.ID(userID))).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "avatar row not found")
	}
	if err != nil {
		return nil, grpcInternal(ctx, "avatar complete query row", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	if av.ObjectKey != req.GetObjectKey() {
		return nil, status.Error(codes.FailedPrecondition, "object_key does not match the active upload session")
	}

	head, err := g.avatars.Store.HeadObject(ctx, g.avatars.UploadBucket, req.GetObjectKey())
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			return nil, status.Error(codes.FailedPrecondition, "object not found in storage")
		}
		return nil, grpcInternal(ctx, "avatar head staging", err, "bucket", g.avatars.UploadBucket, "user_id_prefix", userIDPrefix(userID.String()))
	}
	if head.Size <= 0 || head.Size > media.MaxAvatarStagingBytes {
		return nil, status.Errorf(codes.InvalidArgument, "unreasonable object size %d", head.Size)
	}
	if req.GetByteSize() != head.Size {
		return nil, status.Errorf(codes.InvalidArgument, "byte_size does not match object (head reports %d)", head.Size)
	}

	rc, _, err := g.avatars.Store.GetObject(ctx, g.avatars.UploadBucket, req.GetObjectKey())
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			return nil, status.Error(codes.FailedPrecondition, "object not found in storage")
		}
		return nil, grpcInternal(ctx, "avatar download staging", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	raw, err := readAllLimited(rc, head.Size+1)
	_ = rc.Close()
	if err != nil {
		return nil, grpcInternal(ctx, "avatar read staging", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	if int64(len(raw)) != head.Size {
		return nil, status.Error(codes.InvalidArgument, "downloaded size does not match object metadata")
	}

	canonicalMIME, err := media.ValidateAvatarStagingObject(raw, media.AvatarStagingTrust{
		HeadContentLength: head.Size,
		HeadContentType:   head.ContentType,
		ClientByteSize:    req.GetByteSize(),
	})
	if err != nil {
		if isAvatarValidationErr(err) {
			return nil, status.Error(codes.InvalidArgument, "invalid avatar image")
		}
		return nil, grpcInternal(ctx, "avatar staging validate", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	webpBytes, err := g.avatarProc.ProcessToSquareWebP(raw, canonicalMIME)
	if err != nil {
		if isAvatarValidationErr(err) {
			return nil, status.Error(codes.InvalidArgument, "invalid avatar image")
		}
		return nil, grpcInternal(ctx, "avatar raster process", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	prodKey := fmt.Sprintf("avatars/%s.webp", userID.String())
	if err := g.avatars.Store.PutObject(ctx, g.avatars.AssetsBucket, prodKey, webpBytes, "image/webp"); err != nil {
		return nil, grpcInternal(ctx, "avatar store processed", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	publicURL := g.avatars.publicProdURL(prodKey)
	now := time.Now()

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar complete tx begin", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.UserAvatar.UpdateOneID(av.ID).
		SetObjectKey(prodKey).
		SetUploadedAt(now).
		SetByteSize(int64(len(webpBytes))).
		SetContentType("image/webp").
		Save(ctx); err != nil {
		return nil, grpcInternal(ctx, "avatar complete update row", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if _, err := tx.UserProfile.UpdateOneID(userID).
		SetAvatarURL(publicURL).
		Save(ctx); err != nil {
		return nil, grpcInternal(ctx, "avatar complete update profile", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(ctx, "avatar complete tx commit", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := g.avatars.Store.DeleteObject(ctx, g.avatars.UploadBucket, req.GetObjectKey()); err != nil {
		tid, _ := traceid.FromContext(ctx)
		log.Printf("avatar: delete staging object trace_id=%s object_key=%s err=%v", tid, req.GetObjectKey(), err)
	}

	p, err := g.db.UserProfile.Get(ctx, userID)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar complete reload profile", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := g.publishChange(ctx, userID.String(), p.Email, profileevent.ProfileChangedEvent_CHANGE_TYPE_AVATAR_UPDATED); err != nil {
		return nil, grpcInternal(ctx, "avatar complete publish", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	return &pb.CompleteAvatarUploadResponse{AvatarUrl: publicURL}, nil
}

func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

func isAvatarValidationErr(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, media.ErrEmptyRasterInput),
		errors.Is(err, media.ErrUnsupportedRasterContentType),
		errors.Is(err, media.ErrRasterDecodeFailed),
		errors.Is(err, media.ErrRasterSignatureInvalid),
		errors.Is(err, media.ErrRasterHeadContentTypeMismatch),
		errors.Is(err, media.ErrRasterSniffContentTypeConflict),
		errors.Is(err, media.ErrRasterBodySizeMismatchHEAD),
		errors.Is(err, media.ErrAvatarClientSizeDisagreesWithHEAD),
		errors.Is(err, media.ErrRasterObjectTooLarge),
		errors.Is(err, media.ErrRasterHeadSizeInvalid),
		errors.Is(err, media.ErrRasterDimensionsExceedLimit),
		errors.Is(err, media.ErrRasterClaimedKindMismatch):
		return true
	}
	var d media.DetailError
	if errors.As(err, &d) {
		return true
	}
	return false
}
