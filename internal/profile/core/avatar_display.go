package core

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/useravatar"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/internal/profile/synthavatar"
)

// displayAvatar returns the avatar URL and object key for API responses.
//
// Selection rule (keep in sync with schema comment on UserAvatar): among rows for this user
// where uploaded_at is non-null, take the one with the greatest id (UUID v7 is time-ordered).
// Rows with uploaded_at == nil are in-flight staging uploads and are ignored.
//
// Display URLs are composed from PROFILE_PUBLIC_ASSETS_URL + object_key when avatar storage is
// configured; legacy rows with object_key under virtual/ are treated as non-CDN and fall back
// to an inline synthetic PNG (goavatar) without exposing stored third-party picture URLs.
func (m *Manager) displayAvatar(
	ctx context.Context,
	userID uuid.UUID,
) (avatarURL, objectKey string, err error) {
	av, err := m.db.UserAvatar.Query().
		Where(
			useravatar.HasUserWith(userprofile.ID(userID)),
			useravatar.UploadedAtNotNil(),
		).
		Order(useravatar.ByID(sql.OrderDesc())).
		First(ctx)

	if ent.IsNotFound(err) {
		u, err := synthavatar.DataURL(userID)
		if err != nil {
			return "", "", err
		}
		return u, "", nil
	}
	if err != nil {
		return "", "", err
	}

	if strings.HasPrefix(av.ObjectKey, "virtual/") {
		u, err := synthavatar.DataURL(userID)
		if err != nil {
			return "", "", err
		}
		return u, "", nil
	}

	if m.media != nil && av.ObjectKey != "" {
		return m.media.PublicProdURL(av.ObjectKey), av.ObjectKey, nil
	}

	u, err := synthavatar.DataURL(userID)
	if err != nil {
		return "", "", err
	}

	return u, av.ObjectKey, nil
}
