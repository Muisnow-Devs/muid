package core

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestCreateOrganizationProfileAutoSlug(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "orgcreateauto")
	ctx := context.Background()

	orgID := uuid.New()
	p, err := m.CreateOrganizationProfile(ctx, orgID, "Acme Corp", "", "the org")
	if err != nil {
		t.Fatalf("CreateOrganizationProfile() error = %v", err)
	}
	if p.OrganizationID != orgID {
		t.Errorf("OrganizationID = %v, want %v", p.OrganizationID, orgID)
	}
	if p.Slug != "acme-corp" {
		t.Errorf("Slug = %q, want acme-corp (derived from name)", p.Slug)
	}
	if p.DisplayName != "Acme Corp" || p.Description != "the org" {
		t.Errorf("DisplayName/Description = %q/%q", p.DisplayName, p.Description)
	}
}

func TestCreateOrganizationProfileSlugCollisionSuffixes(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "orgcreatecollide")
	ctx := context.Background()

	if _, err := m.CreateOrganizationProfile(ctx, uuid.New(), "Acme", "acme", ""); err != nil {
		t.Fatalf("seed first org: %v", err)
	}
	p, err := m.CreateOrganizationProfile(ctx, uuid.New(), "Acme", "acme", "")
	if err != nil {
		t.Fatalf("CreateOrganizationProfile() error = %v", err)
	}
	if p.Slug != "acme-2" {
		t.Errorf("Slug = %q, want acme-2 (suffixed on collision)", p.Slug)
	}
}

func TestCreateOrganizationProfileDuplicateOrg(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "orgcreatedup")
	ctx := context.Background()

	orgID := uuid.New()
	if _, err := m.CreateOrganizationProfile(ctx, orgID, "Acme", "", ""); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := m.CreateOrganizationProfile(ctx, orgID, "Acme Again", "", "")
	if !errors.Is(err, ErrOrganizationProfileExists) {
		t.Fatalf("error = %v, want ErrOrganizationProfileExists", err)
	}
}

func TestGetOrganizationProfileNotFound(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "orggetnotfound")

	_, err := m.GetOrganizationProfile(context.Background(), uuid.New())
	if !errors.Is(err, ErrOrganizationProfileNotFound) {
		t.Fatalf("error = %v, want ErrOrganizationProfileNotFound", err)
	}
}

func TestUpdateOrganizationProfile(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "orgupdate")
	ctx := context.Background()

	orgID := uuid.New()
	if _, err := m.CreateOrganizationProfile(ctx, orgID, "Acme", "acme", "old"); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	mask := &fieldmaskpb.FieldMask{Paths: []string{"display_name", "slug", "description"}}
	p, err := m.UpdateOrganizationProfile(ctx, orgID, mask, "Acme Inc", "acme-inc", "new desc")
	if err != nil {
		t.Fatalf("UpdateOrganizationProfile() error = %v", err)
	}
	if p.DisplayName != "Acme Inc" || p.Slug != "acme-inc" || p.Description != "new desc" {
		t.Errorf("updated = %q/%q/%q", p.DisplayName, p.Slug, p.Description)
	}
}

func TestUpdateOrganizationProfileErrors(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "orgupdateerrors")
	ctx := context.Background()

	orgID := uuid.New()
	if _, err := m.CreateOrganizationProfile(ctx, orgID, "Acme", "acme", ""); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	t.Run("not found", func(t *testing.T) {
		_, err := m.UpdateOrganizationProfile(ctx, uuid.New(),
			&fieldmaskpb.FieldMask{Paths: []string{"description"}}, "", "", "x")
		if !errors.Is(err, ErrOrganizationProfileNotFound) {
			t.Fatalf("error = %v, want ErrOrganizationProfileNotFound", err)
		}
	})

	t.Run("slug conflict", func(t *testing.T) {
		other := uuid.New()
		if _, err := m.CreateOrganizationProfile(ctx, other, "Other", "taken-slug", ""); err != nil {
			t.Fatalf("seed conflicting org: %v", err)
		}
		_, err := m.UpdateOrganizationProfile(ctx, orgID,
			&fieldmaskpb.FieldMask{Paths: []string{"slug"}}, "", "taken-slug", "")
		if !errors.Is(err, ErrUpdateConflict) {
			t.Fatalf("error = %v, want ErrUpdateConflict", err)
		}
	})

	t.Run("unsupported path", func(t *testing.T) {
		_, err := m.UpdateOrganizationProfile(ctx, orgID,
			&fieldmaskpb.FieldMask{Paths: []string{"website"}}, "", "", "")
		if !errors.Is(err, ErrUnsupportedMaskPath) {
			t.Fatalf("error = %v, want ErrUnsupportedMaskPath", err)
		}
	})

	t.Run("empty mask", func(t *testing.T) {
		_, err := m.UpdateOrganizationProfile(ctx, orgID, &fieldmaskpb.FieldMask{}, "", "", "")
		var ia InvalidArgumentError
		if !errors.As(err, &ia) {
			t.Fatalf("error = %v, want InvalidArgumentError", err)
		}
	})

	t.Run("invalid slug value", func(t *testing.T) {
		_, err := m.UpdateOrganizationProfile(ctx, orgID,
			&fieldmaskpb.FieldMask{Paths: []string{"slug"}}, "", "Bad_Slug", "")
		var ia InvalidArgumentError
		if !errors.As(err, &ia) {
			t.Fatalf("error = %v, want InvalidArgumentError", err)
		}
	})
}
