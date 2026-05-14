package avataringest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/avatarkey"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/synthavatar"
	"sanzi.io/muid/infra/r2"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/traceid"
)

const ingestTimeout = 3 * time.Minute

// ExternalAvatarIngestor downloads HTTPS avatar sources, validates and rasterizes to WebP,
// uploads to the production assets bucket, and INSERTs append-only UserAvatar rows.
type ExternalAvatarIngestor struct {
	db             *ent.Client
	store          r2.ObjectStore
	assetsBucket   string
	publicAssetURL string
	proc           media.RasterAvatarProcessor
}

// NewExternalAvatarIngestor wires object storage and raster processing for URL-based ingestion.
func NewExternalAvatarIngestor(
	db *ent.Client,
	store r2.ObjectStore,
	assetsBucket, publicAssetURL string,
	proc media.RasterAvatarProcessor,
) *ExternalAvatarIngestor {
	return &ExternalAvatarIngestor{
		db:             db,
		store:          store,
		assetsBucket:   assetsBucket,
		publicAssetURL: publicAssetURL,
		proc:           proc,
	}
}

func userIDPrefix(userID string) string {
	if len(userID) >= 8 {
		return userID[:8]
	}
	return userID
}

func (i *ExternalAvatarIngestor) publicProdURL(objectKey string) string {
	return r2.PublicObjectURL(i.publicAssetURL, objectKey)
}

// prepareAndUploadFromRaw validates raster bytes, converts to WebP, uploads to assets bucket.
func (i *ExternalAvatarIngestor) prepareAndUploadFromRaw(ctx context.Context, userID uuid.UUID, raw []byte, headContentType string) (rowID uuid.UUID, objectKey, publicURL string, byteSize int64, err error) {
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
	if err := i.store.PutObject(ctx, i.assetsBucket, objectKey, webp, media.ContentTypeWebP); err != nil {
		return uuid.Nil, "", "", 0, err
	}
	publicURL = i.publicProdURL(objectKey)
	return rowID, objectKey, publicURL, int64(len(webp)), nil
}

// prepareAndUpload downloads sourceURL, validates, converts to WebP, uploads to assets bucket.
func (i *ExternalAvatarIngestor) prepareAndUpload(ctx context.Context, userID uuid.UUID, sourceURL string) (rowID uuid.UUID, objectKey, publicURL string, byteSize int64, err error) {
	raw, headCT, err := fetchHTTPSAvatarSource(ctx, sourceURL)
	if err != nil {
		return uuid.Nil, "", "", 0, err
	}
	return i.prepareAndUploadFromRaw(ctx, userID, raw, headCT)
}

func (i *ExternalAvatarIngestor) insertCommittedAvatar(ctx context.Context, userID, rowID uuid.UUID, objectKey, publicURL string, byteSize int64) error {
	_, err := i.db.UserAvatar.Create().
		SetID(rowID).
		SetUserID(userID).
		SetObjectKey(objectKey).
		SetContentType(media.ContentTypeWebP).
		SetByteSize(byteSize).
		SetPublicURL(publicURL).
		SetUploadedAt(time.Now()).
		Save(ctx)
	return err
}

// IngestSyntheticLocal generates a deterministic goavatar PNG for userID, then uses the same WebP upload path as HTTPS ingestion.
func (i *ExternalAvatarIngestor) IngestSyntheticLocal(ctx context.Context, userID uuid.UUID) error {
	raw, err := synthavatar.PNGBytes(userID)
	if err != nil {
		return err
	}
	rowID, objectKey, publicURL, byteSize, err := i.prepareAndUploadFromRaw(ctx, userID, raw, "image/png")
	if err != nil {
		return err
	}
	return i.insertCommittedAvatar(ctx, userID, rowID, objectKey, publicURL, byteSize)
}

// IngestFromURL tries primaryURL then optional fallbackURL (when different) before returning an error.
func (i *ExternalAvatarIngestor) IngestFromURL(ctx context.Context, userID uuid.UUID, primaryURL, fallbackURL string) error {
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
func (i *ExternalAvatarIngestor) Go(parentCtx context.Context, userID uuid.UUID, primaryURL, fallbackURL string) {
	if i == nil {
		return
	}
	tid, _ := traceid.FromContext(parentCtx)
	base := context.Background()
	if tid != "" {
		base = traceid.With(base, tid)
	}
	uid := userID
	prim := primaryURL
	fb := fallbackURL
	go func() {
		workCtx, cancel := context.WithTimeout(base, ingestTimeout)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				traceid.LogUnexpected(workCtx, "ExternalAvatarIngestor.panic", fmt.Sprintf("%v", r), "user_id_prefix", userIDPrefix(uid.String()))
			}
		}()
		if err := i.IngestFromURL(workCtx, uid, prim, fb); err != nil {
			traceid.LogUnexpected(workCtx, "ExternalAvatarIngestor.IngestFromURL", err.Error(), "user_id_prefix", userIDPrefix(uid.String()))
		}
	}()
}

// GoBootstrap schedules post-CreateProfile ingestion: when oidcPictureURL is a non-empty https URL it is tried first;
// on failure or when absent, a deterministic local synthetic avatar is ingested (no third-party placeholder URLs).
func (i *ExternalAvatarIngestor) GoBootstrap(parentCtx context.Context, userID uuid.UUID, oidcPictureURL string) {
	if i == nil {
		return
	}
	tid, _ := traceid.FromContext(parentCtx)
	base := context.Background()
	if tid != "" {
		base = traceid.With(base, tid)
	}
	uid := userID
	pic := strings.TrimSpace(oidcPictureURL)
	go func() {
		workCtx, cancel := context.WithTimeout(base, ingestTimeout)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				traceid.LogUnexpected(workCtx, "ExternalAvatarIngestor.GoBootstrap.panic", fmt.Sprintf("%v", r), "user_id_prefix", userIDPrefix(uid.String()))
			}
		}()

		tryURL := pic != "" && strings.HasPrefix(pic, "https://")
		var err error
		if tryURL {
			rowID, objectKey, publicURL, byteSize, prepErr := i.prepareAndUpload(workCtx, uid, pic)
			if prepErr == nil {
				err = i.insertCommittedAvatar(workCtx, uid, rowID, objectKey, publicURL, byteSize)
			} else {
				err = prepErr
			}
		}
		if !tryURL || err != nil {
			err = i.IngestSyntheticLocal(workCtx, uid)
		}
		if err != nil {
			traceid.LogUnexpected(workCtx, "ExternalAvatarIngestor.GoBootstrap", err.Error(), "user_id_prefix", userIDPrefix(uid.String()))
		}
	}()
}
