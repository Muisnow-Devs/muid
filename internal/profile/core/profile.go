package core

import (
	"context"
	"strings"

	"github.com/google/uuid"

	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/shared/tracing"
	"sanzi.io/muid/pkg/utils"
)

// Profile is the read snapshot for GetProfile with presentation defaults
// applied (locale fallback "en", trimmed timezone/bio, display avatar resolved).
type Profile struct {
	ID              uuid.UUID
	DisplayName     string
	Username        string
	AvatarURL       string
	AvatarObjectKey string
	Locale          string
	Timezone        string
	Bio             string
	// OriginalIdentity is the legacy MuID identity; nil when absent.
	OriginalIdentity *string
}

// CreateProfile allocates a unique username, derives display name / locale /
// timezone from optional identity claims, and schedules async avatar bootstrap
// when a picture URL is present. Returns the new profile id.
func (m *Manager) CreateProfile(
	ctx context.Context,
	identity *idclaims.IdentityInformation,
) (uuid.UUID, error) {
	var (
		displayName = displayNameFromIdentity(identity)
		pictureURL  = avatarFromIdentity(identity)
		locale      string
		timezone    string
	)

	if identity != nil {
		locale = strings.TrimSpace(identity.GetLocale())
		timezone = strings.TrimSpace(identity.GetTimezone())
	}

	utils.DefaultIfEmpty(&locale, "en")
	utils.DefaultIfEmpty(&timezone, "UTC")

	candidates := generateUsernameCandidates(randomUsernameBase())
	ctx = tracing.WithSpanName(ctx, "profile.create_profile.tx")
	user, err := enttx.Run(
		ctx,
		m.db.Tx,
		func(ctx context.Context, tx *ent.Tx) (*ent.UserProfile, error) {
			return createProfileRow(ctx, tx, candidates, displayName, locale, timezone)
		},
	)
	if err != nil {
		return uuid.Nil, err
	}

	if m.ingest != nil && pictureURL != "" {
		m.ingest.GoBootstrap(ctx, user.ID, pictureURL)
	}

	return user.ID, nil
}

// createProfileRow tries each username candidate until an insert succeeds.
// A unique-constraint failure means the candidate raced with another insert;
// the next candidate is tried. ErrUsernameExhausted when all are taken.
func createProfileRow(
	ctx context.Context,
	tx *ent.Tx,
	candidates []string,
	displayName, locale, timezone string,
) (*ent.UserProfile, error) {
	for _, candidate := range candidates {
		exists, err := tx.UserProfile.Query().
			Where(userprofile.UsernameEQ(candidate)).
			Exist(ctx)
		if err != nil {
			return nil, err
		}
		if exists {
			continue
		}

		user, err := tx.UserProfile.Create().
			SetLocale(locale).
			SetTimezone(timezone).
			SetDisplayName(displayName).
			SetUsername(candidate).
			Save(ctx)
		if err == nil {
			return user, nil
		}
		if !ent.IsConstraintError(err) {
			return nil, err
		}
	}

	return nil, ErrUsernameExhausted
}

// GetProfile loads the profile row, original identity edge, and display avatar.
func (m *Manager) GetProfile(ctx context.Context, userID uuid.UUID) (Profile, error) {
	p, err := m.db.UserProfile.Query().
		WithOriginalIdentity().
		Where(userprofile.ID(userID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return Profile{}, ErrProfileNotFound
	}
	if err != nil {
		return Profile{}, err
	}

	locale := "en"
	if strings.TrimSpace(p.Locale) != "" {
		locale = p.Locale
	}

	avatarURL, objectKey, err := m.displayAvatar(ctx, userID)
	if err != nil {
		return Profile{}, err
	}

	out := Profile{
		ID:              p.ID,
		DisplayName:     p.DisplayName,
		Username:        p.Username,
		AvatarURL:       avatarURL,
		AvatarObjectKey: objectKey,
		Locale:          locale,
		Timezone:        strings.TrimSpace(p.Timezone),
		Bio:             strings.TrimSpace(p.Biography),
	}

	if p.Edges.OriginalIdentity != nil {
		oi := p.Edges.OriginalIdentity.OriginalIdentity
		out.OriginalIdentity = &oi
	}

	return out, nil
}
