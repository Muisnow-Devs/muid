package core

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/organizationprofile"
	"sanzi.io/muid/pkg/validation"
)

// OrganizationProfile is the read snapshot for an organization's basic
// information. The OrganizationID is the authz organization id.
type OrganizationProfile struct {
	OrganizationID uuid.UUID
	Slug           string
	DisplayName    string
	Description    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func toOrganizationProfile(row *ent.OrganizationProfile) OrganizationProfile {
	return OrganizationProfile{
		OrganizationID: row.ID,
		Slug:           row.Slug,
		DisplayName:    row.DisplayName,
		Description:    row.Description,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

// CreateOrganizationProfile creates the profile row for an authz organization,
// allocating a unique slug. When slug is empty a base is derived from
// displayName; in both cases the slug is uniquified by suffixing on collision
// (never failing), mirroring username allocation in CreateProfile.
func (m *Manager) CreateOrganizationProfile(
	ctx context.Context,
	organizationID uuid.UUID,
	displayName, slug, description string,
) (OrganizationProfile, error) {
	displayName = strings.TrimSpace(displayName)

	exists, err := m.db.OrganizationProfile.Query().
		Where(organizationprofile.ID(organizationID)).
		Exist(ctx)
	if err != nil {
		return OrganizationProfile{}, err
	}
	if exists {
		return OrganizationProfile{}, ErrOrganizationProfileExists
	}

	base := strings.TrimSpace(slug)
	if base == "" {
		base = slugifyDisplayName(displayName)
	}

	for _, candidate := range generateSlugCandidates(base) {
		if !validation.ValidOrgSlug(candidate) {
			continue
		}
		taken, err := m.db.OrganizationProfile.Query().
			Where(organizationprofile.SlugEQ(candidate)).
			Exist(ctx)
		if err != nil {
			return OrganizationProfile{}, err
		}
		if taken {
			continue
		}

		row, err := m.db.OrganizationProfile.Create().
			SetID(organizationID).
			SetSlug(candidate).
			SetDisplayName(displayName).
			SetDescription(strings.TrimSpace(description)).
			Save(ctx)
		if err == nil {
			return toOrganizationProfile(row), nil
		}
		if ent.IsConstraintError(err) {
			continue
		}
		return OrganizationProfile{}, err
	}

	return OrganizationProfile{}, ErrSlugExhausted
}

// GetOrganizationProfile loads the profile row for an organization id.
func (m *Manager) GetOrganizationProfile(
	ctx context.Context,
	organizationID uuid.UUID,
) (OrganizationProfile, error) {
	row, err := m.db.OrganizationProfile.Get(ctx, organizationID)
	if ent.IsNotFound(err) {
		return OrganizationProfile{}, ErrOrganizationProfileNotFound
	}
	if err != nil {
		return OrganizationProfile{}, err
	}
	return toOrganizationProfile(row), nil
}

// UpdateOrganizationProfile applies the masked subset of display_name, slug,
// and description. A slug collision surfaces as ErrUpdateConflict.
func (m *Manager) UpdateOrganizationProfile(
	ctx context.Context,
	organizationID uuid.UUID,
	mask *fieldmaskpb.FieldMask,
	displayName, slug, description string,
) (OrganizationProfile, error) {
	paths := mask.GetPaths()
	if len(paths) == 0 {
		return OrganizationProfile{}, NewInvalidArgumentError(
			"update_mask must list at least one field path",
		)
	}

	update := m.db.OrganizationProfile.UpdateOneID(organizationID)
	for _, raw := range paths {
		switch strings.TrimSpace(raw) {
		case "display_name", "displayName":
			value := strings.TrimSpace(displayName)
			if value == "" {
				return OrganizationProfile{}, NewInvalidArgumentError(
					"display_name must not be empty",
				)
			}
			update.SetDisplayName(value)
		case "slug":
			value := strings.TrimSpace(slug)
			if !validation.ValidOrgSlug(value) {
				return OrganizationProfile{}, NewInvalidArgumentError("invalid slug")
			}
			update.SetSlug(value)
		case "description":
			update.SetDescription(strings.TrimSpace(description))
		default:
			return OrganizationProfile{}, ErrUnsupportedMaskPath
		}
	}

	row, err := update.Save(ctx)
	if ent.IsNotFound(err) {
		return OrganizationProfile{}, ErrOrganizationProfileNotFound
	}
	if ent.IsConstraintError(err) {
		return OrganizationProfile{}, ErrUpdateConflict
	}
	if err != nil {
		return OrganizationProfile{}, err
	}
	return toOrganizationProfile(row), nil
}
