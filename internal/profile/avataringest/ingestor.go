package avataringest

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/avatarkey"
	"sanzi.io/muid/internal/profile/core"
	"sanzi.io/muid/internal/profile/synthavatar"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/tracing"
)

const ingestTimeout = 3 * time.Minute

// CommittedAvatarStore persists display-ready avatar rows (implemented by core.AvatarRepo).
type CommittedAvatarStore interface {
	InsertCommittedAvatar(
		ctx context.Context,
		userID, rowID uuid.UUID,
		objectKey, publicURL string,
		byteSize int64,
	) error
}

// ExternalAvatarIngestor downloads HTTPS avatar sources, validates and rasterizes to WebP,
// uploads to the production assets bucket, and INSERTs append-only UserAvatar rows.
type ExternalAvatarIngestor struct {
	rows  CommittedAvatarStore
	media *core.AvatarMedia
	proc  media.RasterAvatarProcessor
}

// NewExternalAvatarIngestor wires object storage and raster processing for URL-based ingestion.
func NewExternalAvatarIngestor(
	rows CommittedAvatarStore,
	avatarMedia *core.AvatarMedia,
	proc media.RasterAvatarProcessor,
) *ExternalAvatarIngestor {
	return &ExternalAvatarIngestor{
		rows:  rows,
		media: avatarMedia,
		proc:  proc,
	}
}

// prepareAndUploadFromRaw validates raster bytes, converts to WebP, uploads to assets bucket.
func (i *ExternalAvatarIngestor) prepareAndUploadFromRaw(
	ctx context.Context,
	userID uuid.UUID,
	raw []byte,
	headContentType string,
) (rowID uuid.UUID, objectKey, publicURL string, byteSize int64, err error) {
	n := int64(len(raw))
	canonicalMIME, err := media.ValidateAvatarStagingObject(raw, media.AvatarStagingTrust{
		HeadContentLength: n,
		HeadContentType:   headContentType,
		ClientByteSize:    n,
	})
	if err != nil {
		return uuid.Nil, "", "", 0, err
	}
	webp, err := i.proc.ProcessToSquareWebP(raw, canonicalMIME)
	if err != nil {
		return uuid.Nil, "", "", 0, err
	}
	rowID = shared.UUIDV7()
	objectKey = avatarkey.ProductionWebPObjectKey(userID.String(), rowID.String())
	ctx, putSpan := tracing.StartSpan(ctx, "avataringest.upload")
	err = i.media.Store.PutObject(
		ctx,
		i.media.AssetsBucket,
		objectKey,
		webp,
		media.ContentTypeWebP,
	)
	putSpan.End()
	if err != nil {
		return uuid.Nil, "", "", 0, err
	}
	publicURL = i.media.PublicProdURL(objectKey)
	return rowID, objectKey, publicURL, int64(len(webp)), nil
}

// prepareAndUpload downloads sourceURL, validates, converts to WebP, uploads to assets bucket.
func (i *ExternalAvatarIngestor) prepareAndUpload(
	ctx context.Context,
	userID uuid.UUID,
	sourceURL string,
) (rowID uuid.UUID, objectKey, publicURL string, byteSize int64, err error) {
	raw, headCT, err := fetchHTTPSAvatarSource(ctx, sourceURL)
	if err != nil {
		return uuid.Nil, "", "", 0, err
	}
	return i.prepareAndUploadFromRaw(ctx, userID, raw, headCT)
}

func (i *ExternalAvatarIngestor) insertCommittedAvatar(
	ctx context.Context,
	userID, rowID uuid.UUID,
	objectKey, publicURL string,
	byteSize int64,
) error {
	return i.rows.InsertCommittedAvatar(ctx, userID, rowID, objectKey, publicURL, byteSize)
}

// IngestSyntheticLocal generates a deterministic goavatar PNG for userID, then uses the same WebP upload path as HTTPS ingestion.
func (i *ExternalAvatarIngestor) IngestSyntheticLocal(ctx context.Context, userID uuid.UUID) error {
	raw, err := synthavatar.PNGBytes(userID)
	if err != nil {
		return err
	}
	rowID, objectKey, publicURL, byteSize, err := i.prepareAndUploadFromRaw(
		ctx,
		userID,
		raw,
		"image/png",
	)
	if err != nil {
		return err
	}
	return i.insertCommittedAvatar(ctx, userID, rowID, objectKey, publicURL, byteSize)
}

// IngestFromURL tries primaryURL then optional fallbackURL (when different) before returning an error.
func (i *ExternalAvatarIngestor) IngestFromURL(
	ctx context.Context,
	userID uuid.UUID,
	primaryURL, fallbackURL string,
) error {
	rowID, objectKey, publicURL, byteSize, err := i.prepareAndUpload(ctx, userID, primaryURL)
	if err != nil && primaryURL != fallbackURL {
		rowID, objectKey, publicURL, byteSize, err = i.prepareAndUpload(ctx, userID, fallbackURL)
	}
	if err != nil {
		return err
	}
	return i.insertCommittedAvatar(ctx, userID, rowID, objectKey, publicURL, byteSize)
}

// Go runs IngestFromURL in a new goroutine using a fresh context with timeout and propagated trace id.
func (i *ExternalAvatarIngestor) Go(
	parentCtx context.Context,
	userID uuid.UUID,
	primaryURL, fallbackURL string,
) {
	if i == nil {
		return
	}

	ctx := context.WithoutCancel(parentCtx)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ctx = log.WithAttrs(ctx, log.UserID(userID))

	go func() {
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				log.LogUnexpected(ctx, "ExternalAvatarIngestor.panic", fmt.Sprintf("%v", r))
			}
		}()

		if err := i.IngestFromURL(ctx, userID, primaryURL, fallbackURL); err != nil {
			log.LogUnexpected(ctx, "ExternalAvatarIngestor.IngestFromURL", err.Error())
		}
	}()
}

// GoBootstrap schedules post-CreateProfile ingestion: when oidcPictureURL is a non-empty https URL it is tried first;
// on failure or when absent, a deterministic local synthetic avatar is ingested (no third-party placeholder URLs).
func (i *ExternalAvatarIngestor) GoBootstrap(
	parentCtx context.Context,
	userID uuid.UUID,
	oidcPictureURL string,
) {
	if i == nil {
		return
	}

	ctx := context.WithoutCancel(parentCtx)
	if tr, ok := tracing.TracerFromContext(parentCtx); ok {
		ctx = tracing.ContextWithTracer(ctx, tr)
	}
	ctx, cancel := context.WithTimeout(ctx, ingestTimeout)
	ctx = log.WithAttrs(ctx, log.UserID(userID))

	go func() {
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				log.LogUnexpected(
					ctx,
					"ExternalAvatarIngestor.GoBootstrap.panic",
					fmt.Sprintf("%v", r),
				)
			}
		}()

		ctx, span := tracing.StartSpan(ctx, "avataringest.bootstrap")
		defer span.End()

		i.backgroundIngest(
			ctx,
			userID,
			strings.TrimSpace(oidcPictureURL),
		)
	}()
}

func (i *ExternalAvatarIngestor) backgroundIngest(
	ctx context.Context,
	uid uuid.UUID,
	pic string,
) {
	u, err := url.Parse(pic)
	tryURL := err == nil && u.Scheme == "https" && u.Host != ""

	if tryURL {
		ctx, prepSpan := tracing.StartSpan(ctx, "avataringest.prepare_upload")
		rowID, objectKey, publicURL, byteSize, prepErr := i.prepareAndUpload(ctx, uid, pic)
		prepSpan.End()
		if prepErr == nil {
			err = i.insertCommittedAvatar(ctx, uid, rowID, objectKey, publicURL, byteSize)
		} else {
			err = prepErr
		}
	}

	if !tryURL || err != nil {
		err = i.IngestSyntheticLocal(ctx, uid)
	}

	if err != nil {
		log.LogUnexpected(ctx, "ExternalAvatarIngestor.GoBootstrap", err.Error())
	}
}
