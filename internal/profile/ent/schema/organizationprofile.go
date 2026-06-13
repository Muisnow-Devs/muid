package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/validation"
)

// OrganizationProfile holds the editable basic information for an
// organization. The id is the authz organization id (set by the caller, not
// generated here); authz owns the organization's identity and membership.
type OrganizationProfile struct {
	ent.Schema
}

// Fields of the OrganizationProfile.
func (OrganizationProfile) Fields() []ent.Field {
	return []ent.Field{
		// id mirrors the authz organization UUID; assigned explicitly on
		// create, so there is no default generator.
		field.UUID("id", uuid.UUID{}).Immutable(),

		field.String("slug").NotEmpty().Unique().Validate(validation.CheckOrgSlug),
		field.String("display_name").NotEmpty(),
		field.String("description").Default("").MaxLen(255),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Indexes of the OrganizationProfile.
func (OrganizationProfile) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("slug"),
	}
}
