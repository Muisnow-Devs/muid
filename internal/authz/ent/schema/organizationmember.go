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

// OrganizationMember holds the schema definition for the OrganizationMember entity.
type OrganizationMember struct {
	ent.Schema
}

// Fields of the OrganizationMember.
func (OrganizationMember) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("organization_id", uuid.UUID{}).Immutable(),
		field.UUID("user_id", uuid.UUID{}).Immutable(),

		// role_id references the OrganizationRole assigned to this member.
		field.UUID("role_id", uuid.UUID{}),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (OrganizationMember) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id", "user_id").Unique(),
		index.Fields("user_id"),
		index.Fields("role_id"),
	}
}

// Edges of the OrganizationMember.
func (OrganizationMember) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("members").
			Unique().
			Field("organization_id").
			Required().
			Immutable(),
		edge.From("user", UserRef.Type).
			Ref("organization_memberships").
			Unique().
			Field("user_id").
			Required().
			Immutable(),
		edge.From("role", OrganizationRole.Type).
			Ref("members").
			Unique().
			Field("role_id").
			Required(),
	}
}
