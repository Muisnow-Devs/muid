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

// RolePermission holds the schema definition for the RolePermission entity.
//
// Each row grants a single permission string to a role.
// Permission identifiers follow the same "resource:action" convention as
// OIDCScope IDs (e.g. "organization:write", "member:invite").
type RolePermission struct {
	ent.Schema
}

// Fields of the RolePermission.
func (RolePermission) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("role_id", uuid.UUID{}).Immutable(),

		// permission is a "resource:action" string, e.g. "member:invite", "organization:write".
		field.String("permission").
			NotEmpty().
			MaxLen(128).
			Immutable().
			Comment("Permission identifier following the \"resource:action\" convention."),

		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (RolePermission) Indexes() []ent.Index {
	return []ent.Index{
		// A role cannot hold the same permission twice.
		index.Fields("role_id", "permission").Unique(),
		index.Fields("permission"),
	}
}

// Edges of the RolePermission.
func (RolePermission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("role", OrganizationRole.Type).
			Ref("permissions").
			Unique().
			Field("role_id").
			Required().
			Immutable(),
	}
}
