package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/avatarkey"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/useravatar"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/pkg/audit"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/storage"
	"sanzi.io/muid/pkg/shared/tracing"
)

const stagingCleanupTimeout = 10 * time.Second

// AvatarUploadSession describes a presigned staging upload.
type AvatarUploadSession struct {
	UploadURL string
	ObjectKey string
	ExpiresAt time.Time
}

// StartAvatarUpload presigns a staging PUT and records a pending UserAvatar row.
// Stale pending rows for the same user are deleted in the same transaction
// (their staging objects are cleaned up best-effort afterwards), so at most one
// upload session is in flight per user.
func (m *Manager) StartAvatarUpload(
	ctx context.Context,
	userID uuid.UUID,
	contentType string,
) (AvatarUploadSession, error) {
	if m.media == nil {
		return AvatarUploadSession{}, ErrAvatarNotConfigured
	}

	_, err := m.db.UserProfile.Get(ctx, userID)
	if ent.IsNotFound(err) {
		return AvatarUploadSession{}, ErrProfileNotFound
	}
	if err != nil {
		return AvatarUploadSession{}, err
	}

	ct := strings.TrimSpace(contentType)
	if !media.AllowedRasterContentType(ct) {
		return AvatarUploadSession{}, NewInvalidArgumentError(fmt.Sprintf(
			"unsupported content type %q (use image/jpeg, image/png, image/gif, or image/webp)",
			ct,
		))
	}

	objectKey := avatarkey.StagingObjectKey(userID.String(), shared.UUIDV7().String())
	exp := 15 * time.Minute
	ctx, span := tracing.StartSpan(ctx, "profile.avatar.presign_put")
	defer span.End()
	url, expTime, err := m.media.Store.PresignPut(ctx, m.media.UploadBucket, objectKey, ct, exp)
	if err != nil {
		span.RecordError(err)
		return AvatarUploadSession{}, err
	}

	var staleKeys []string
	err = enttx.Do(ctx, m.db.Tx, func(ctx context.Context, tx *ent.Tx) error {
		pendingRows := tx.UserAvatar.Query().Where(
			useravatar.HasUserWith(userprofile.ID(userID)),
			useravatar.UploadedAtIsNil(),
		)
		stale, err := pendingRows.All(ctx)
		if err != nil {
			return err
		}
		staleKeys = staleKeys[:0]
		for _, row := range stale {
			staleKeys = append(staleKeys, row.ObjectKey)
		}
		if len(stale) > 0 {
			_, err = tx.UserAvatar.Delete().Where(
				useravatar.HasUserWith(userprofile.ID(userID)),
				useravatar.UploadedAtIsNil(),
			).Exec(ctx)
			if err != nil {
				return err
			}
		}

		_, err = tx.UserAvatar.Create().
			SetID(shared.UUIDV7()).
			SetUserID(userID).
			SetObjectKey(objectKey).
			SetContentType(ct).
			SetByteSize(0).
			Save(ctx)
		return err
	})
	if err != nil {
		return AvatarUploadSession{}, err
	}

	m.goDeleteStagingObjects(ctx, staleKeys)

	return AvatarUploadSession{
		UploadURL: url,
		ObjectKey: objectKey,
		ExpiresAt: expTime.UTC(),
	}, nil
}

// CompleteAvatarUpload validates and processes the staged object, stores the
// WebP in the assets bucket, swaps the pending row for a committed one in a
// single transaction, then asynchronously deletes the staging object and
// publishes the change event. Returns the public avatar URL.
func (m *Manager) CompleteAvatarUpload(
	ctx context.Context,
	userID uuid.UUID,
	objectKey string,
	byteSize int64,
) (string, error) {
	if m.media == nil {
		return "", ErrAvatarNotConfigured
	}

	if !strings.HasPrefix(objectKey, avatarkey.UserObjectPrefix(userID.String())) {
		return "", ErrObjectKeyNotOwned
	}

	av, err := m.db.UserAvatar.Query().
		Where(
			useravatar.HasUserWith(userprofile.ID(userID)),
			useravatar.ObjectKeyEQ(objectKey),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return "", ErrAvatarSessionNotFound
	}
	if err != nil {
		return "", err
	}
	if av.UploadedAt != nil {
		return "", ErrAvatarSessionCompleted
	}

	ctx, getSpan := tracing.StartSpan(ctx, "profile.avatar.get_object")
	defer getSpan.End()
	rc, head, err := m.media.Store.GetObject(ctx, m.media.UploadBucket, objectKey)
	if err != nil {
		getSpan.RecordError(err)
		if errors.Is(err, storage.ErrObjectNotFound) {
			return "", ErrAvatarObjectMissing
		}
		return "", err
	}
	defer errutil.Close(rc)

	if head.Size <= 0 || head.Size > media.MaxAvatarStagingBytes {
		return "", NewInvalidArgumentError(fmt.Sprintf("unreasonable object size %d", head.Size))
	}
	if byteSize != head.Size {
		return "", NewInvalidArgumentError(fmt.Sprintf(
			"byte_size does not match object (head reports %d)",
			head.Size,
		))
	}

	raw, err := io.ReadAll(io.LimitReader(rc, head.Size+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) != head.Size {
		return "", NewInvalidArgumentError("downloaded size does not match object metadata")
	}

	canonicalMIME, err := media.ValidateAvatarStagingObject(raw, media.AvatarStagingTrust{
		HeadContentLength: head.Size,
		HeadContentType:   head.ContentType,
		ClientByteSize:    byteSize,
	})
	if err != nil {
		if isAvatarValidationErr(err) {
			return "", errors.Join(ErrInvalidAvatarImage, err)
		}
		return "", err
	}

	ctx, procSpan := tracing.StartSpan(ctx, "profile.avatar.raster_process")
	defer procSpan.End()
	webpBytes, err := m.proc.ProcessToSquareWebP(raw, canonicalMIME)
	if err != nil {
		procSpan.RecordError(err)
		if isAvatarValidationErr(err) {
			return "", errors.Join(ErrInvalidAvatarImage, err)
		}
		return "", err
	}

	finalRowID := shared.UUIDV7()
	prodKey := avatarkey.ProductionWebPObjectKey(userID.String(), finalRowID.String())
	ctx, putSpan := tracing.StartSpan(ctx, "profile.avatar.put_object")
	defer putSpan.End()
	err = m.media.Store.PutObject(
		ctx,
		m.media.AssetsBucket,
		prodKey,
		webpBytes,
		media.ContentTypeWebP,
	)
	if err != nil {
		putSpan.RecordError(err)
		return "", err
	}

	publicURL := m.media.PublicProdURL(prodKey)
	now := time.Now()

	ctx = tracing.WithSpanName(ctx, "profile.complete_avatar_upload.tx")
	err = enttx.Do(ctx, m.db.Tx, func(ctx context.Context, tx *ent.Tx) error {
		// The pending row is consumed by this completion; only committed
		// (uploaded_at != nil) rows are append-only history.
		err := tx.UserAvatar.DeleteOneID(av.ID).Exec(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return err
		}

		_, err = tx.UserAvatar.Create().
			SetID(finalRowID).
			SetUserID(userID).
			SetObjectKey(prodKey).
			SetUploadedAt(now).
			SetByteSize(int64(len(webpBytes))).
			SetContentType(media.ContentTypeWebP).
			SetPublicURL(publicURL).
			Save(ctx)
		if err != nil {
			return err
		}
		return writeAudit(ctx, tx, audit.Entry{
			Action:       audit.ActionProfileAvatarUpdate,
			ResourceType: audit.ResourceAvatar,
			ResourceID:   userID.String(),
			Changes: audit.Changes(nil, map[string]any{
				"avatar_id":  finalRowID.String(),
				"object_key": prodKey,
				"public_url": publicURL,
			}),
		})
	})
	if err != nil {
		return "", err
	}

	// Cleanup and event publish must survive the request returning.
	go func() {
		bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stagingCleanupTimeout)
		defer cancel()

		err := m.media.Store.DeleteObject(bgCtx, m.media.UploadBucket, objectKey)
		if err != nil {
			log.Logger(bgCtx).Info("avatar delete staging object",
				slog.String("object_key", objectKey),
				slog.Any("err", err),
			)
		}

		claims := claimsWithPicture(publicURL)
		m.publishProfileChanged(bgCtx, userID, []string{"avatar_object_key", "avatar_url"}, claims)
	}()

	return publicURL, nil
}

// goDeleteStagingObjects best-effort deletes superseded staging objects in the
// background; failures are logged (the R2 lifecycle rule is the catchall).
func (m *Manager) goDeleteStagingObjects(ctx context.Context, objectKeys []string) {
	if len(objectKeys) == 0 {
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stagingCleanupTimeout)
		defer cancel()

		for _, key := range objectKeys {
			err := m.media.Store.DeleteObject(bgCtx, m.media.UploadBucket, key)
			if err != nil {
				log.Logger(bgCtx).Info("avatar delete stale staging object",
					slog.String("object_key", key),
					slog.Any("err", err),
				)
			}
		}
	}()
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

	_, ok := errors.AsType[media.DetailError](err)
	return ok
}
