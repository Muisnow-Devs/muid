package core

import (
	"context"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
)

// AvatarRepo is the narrow persistence surface avataringest needs: it can only
// INSERT display-ready avatar rows, keeping the ent client out of that package.
type AvatarRepo struct {
	db *ent.Client
}

func NewAvatarRepo(db *ent.Client) *AvatarRepo {
	return &AvatarRepo{db: db}
}

// InsertCommittedAvatar records a processed WebP avatar as immediately
// displayable (uploaded_at = now).
func (r *AvatarRepo) InsertCommittedAvatar(
	ctx context.Context,
	userID, rowID uuid.UUID,
	objectKey, publicURL string,
	byteSize int64,
) error {
	_, err := r.db.UserAvatar.Create().
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
