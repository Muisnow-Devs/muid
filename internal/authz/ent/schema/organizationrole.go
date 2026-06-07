package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// OrganizationRole holds the schema definition for the OrganizationRole entity.
//
// Roles belong to a single organization. System roles (owner, admin, member) are
// seeded automatically when an organization is created and may not be deleted.
// Custom roles are created by organization admins.
type OrganizationRole struct {
	ent.Schema
}

// Fields of the OrganizationRole.
func (OrganizationRole) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("organization_id", uuid.UUID{}).Immutable(),

		// name is unique within an organization (enforced by the composite index below).
		field.String("name").NotEmpty().MaxLen(64),

		field.String("description").MaxLen(255).Optional(),

		// is_system marks built-in roles (e.g. "owner", "admin", "member") that cannot
		// be deleted and whose names cannot be changed.
		field.Bool("is_system").Default(false).Immutable(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (OrganizationRole) Indexes() []ent.Index {
	return []ent.Index{
		// Role names must be unique within an organization.
		index.Fields("organization_id", "name").Unique(),
		index.Fields("organization_id"),
	}
}

// Edges of the OrganizationRole.
func (OrganizationRole) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("roles").
			Unique().
			Field("organization_id").
			Required().
			Immutable(),

		edge.To("permissions", RolePermission.Type),

		edge.To("members", OrganizationMember.Type),
	}
}
