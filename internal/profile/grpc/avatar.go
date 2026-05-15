package profilegrpc

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/avatarkey"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/useravatar"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/internal/profile/updatemask"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/storage"
	"sanzi.io/muid/pkg/traceid"
)

const msgInvalidUserID = "invalid user id"

func (g *GRPCHandler) StartAvatarUpload(
	ctx context.Context,
	req *pb.StartAvatarUploadRequest,
) (*pb.StartAvatarUploadResponse, error) {
	if g.avatars == nil {
		return nil, status.Error(
			codes.FailedPrecondition,
			"avatar uploads are not configured (set PROFILE_R2_* variables)",
		)
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, msgInvalidUserID)
	}

	if _, err := g.db.UserProfile.Get(ctx, userID); ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "profile not found")
	} else if err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar start profile lookup", userID)
	}

	ct := strings.TrimSpace(req.GetContentType())
	if !media.AllowedRasterContentType(ct) {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"unsupported content type %q (use image/jpeg, image/png, image/gif, or image/webp)",
			ct,
		)
	}

	objectKey := avatarkey.StagingObjectKey(userID.String(), shared.UUIDV7().String())
	exp := 15 * time.Minute
	url, expTime, err := g.avatars.Store.PresignPut(ctx, g.avatars.UploadBucket, objectKey, ct, exp)
	if err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar presign put", userID)
	}

	sessID := shared.UUIDV7()
	_, err = g.db.UserAvatar.Create().
		SetID(sessID).
		SetUserID(userID).
		SetObjectKey(objectKey).
		SetContentType(ct).
		SetByteSize(0).
		Save(ctx)
	if err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar start record pending", userID)
	}

	resp := &pb.StartAvatarUploadResponse{}
	resp.SetUploadUrl(url)
	resp.SetObjectKey(objectKey)
	resp.SetExpiresAt(timestamppb.New(expTime.UTC()))
	return resp, nil
}

func (g *GRPCHandler) CompleteAvatarUpload(
	ctx context.Context,
	req *pb.CompleteAvatarUploadRequest,
) (*pb.CompleteAvatarUploadResponse, error) {
	if g.avatars == nil {
		return nil, status.Error(
			codes.FailedPrecondition,
			"avatar uploads are not configured (set PROFILE_R2_* variables)",
		)
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, msgInvalidUserID)
	}
	if !strings.HasPrefix(req.GetObjectKey(), avatarkey.UserObjectPrefix(userID.String())) {
		return nil, status.Error(codes.InvalidArgument, "object_key does not belong to this user")
	}

	av, err := g.db.UserAvatar.Query().
		Where(
			useravatar.HasUserWith(userprofile.ID(userID)),
			useravatar.ObjectKeyEQ(req.GetObjectKey()),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "avatar row not found")
	}
	if err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar complete query row", userID)
	}
	if av.ObjectKey != req.GetObjectKey() {
		return nil, status.Error(
			codes.FailedPrecondition,
			"object_key does not match the active upload session",
		)
	}
	if av.UploadedAt != nil {
		return nil, status.Error(codes.FailedPrecondition, "upload session already completed")
	}

	rc, head, err := g.avatars.Store.GetObject(ctx, g.avatars.UploadBucket, req.GetObjectKey())
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			return nil, status.Error(codes.FailedPrecondition, "object not found in storage")
		}
		return nil, internalErrorWithUserId(
			ctx,
			err,
			"avatar download staging",
			userID,
			"bucket",
			g.avatars.UploadBucket,
		)
	}
	defer errutil.Close(rc)

	if head.Size <= 0 || head.Size > media.MaxAvatarStagingBytes {
		return nil, status.Errorf(codes.InvalidArgument, "unreasonable object size %d", head.Size)
	}
	if req.GetByteSize() != head.Size {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"byte_size does not match object (head reports %d)",
			head.Size,
		)
	}

	raw, err := readAllLimited(rc, head.Size+1)
	if err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar read staging", userID)
	}
	if int64(len(raw)) != head.Size {
		return nil, status.Error(
			codes.InvalidArgument,
			"downloaded size does not match object metadata",
		)
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
		return nil, internalErrorWithUserId(ctx, err, "avatar staging validate", userID)
	}

	webpBytes, err := g.avatarProc.ProcessToSquareWebP(raw, canonicalMIME)
	if err != nil {
		if isAvatarValidationErr(err) {
			return nil, status.Error(codes.InvalidArgument, "invalid avatar image")
		}
		return nil, internalErrorWithUserId(ctx, err, "avatar raster process", userID)
	}

	finalRowID := shared.UUIDV7()
	prodKey := avatarkey.ProductionWebPObjectKey(userID.String(), finalRowID.String())
	if err := g.avatars.Store.PutObject(
		ctx,
		g.avatars.AssetsBucket,
		prodKey,
		webpBytes,
		media.ContentTypeWebP,
	); err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar store processed", userID)
	}

	publicURL := g.avatars.publicProdURL(prodKey)
	now := time.Now()

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar complete tx begin", userID)
	}
	defer func() { errutil.Discard(tx.Rollback()) }()

	if _, err := tx.UserAvatar.Create().
		SetID(finalRowID).
		SetUserID(userID).
		SetObjectKey(prodKey).
		SetUploadedAt(now).
		SetByteSize(int64(len(webpBytes))).
		SetContentType(media.ContentTypeWebP).
		SetPublicURL(publicURL).
		Save(ctx); err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar complete insert row", userID)
	}

	if err := tx.Commit(); err != nil {
		return nil, internalErrorWithUserId(ctx, err, "avatar complete tx commit", userID)
	}

	// Async non-blocking operations for cleanup and publishing
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tid, _ := traceid.FromContext(ctx)
		bgCtx = traceid.With(bgCtx, tid)

		err := g.avatars.Store.DeleteObject(bgCtx, g.avatars.UploadBucket, req.GetObjectKey())
		if err != nil {
			log.Printf(
				"avatar: delete staging object trace_id=%s object_key=%s err=%v",
				tid,
				req.GetObjectKey(),
				err,
			)
		}

		avPaths, err := updatemask.SortedUniqueGetProfileResponsePaths(
			[]string{"avatar_url", "avatar_object_key"},
		)
		if err == nil {
			changed := &fieldmaskpb.FieldMask{Paths: avPaths}
			g.publishChange(bgCtx, userID.String(), changed)
		}
	}()

	resp := &pb.CompleteAvatarUploadResponse{}
	resp.SetAvatarUrl(publicURL)
	return resp, nil
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
