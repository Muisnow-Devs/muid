package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// Organization holds the schema definition for the Organization entity.
type Organization struct {
	ent.Schema
}

// Fields of the Organization.
func (Organization) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		// Denormalized display fields used by authz's own membership/admin
		// lists; the editable source of truth (slug, display name,
		// description) lives in the profile service's OrganizationProfile.
		// name is not unique — the unique handle is the profile slug.
		field.String("name").NotEmpty(),
		field.String("description").MaxLen(255).Optional(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the Organization.
func (Organization) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("members", OrganizationMember.Type),
		edge.To("roles", OrganizationRole.Type),
	}
}
