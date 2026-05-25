package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// UserRef holds the schema definition for the UserRef entity.
type UserRef struct {
	ent.Schema
}

// Fields of the UserRef.
func (UserRef) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the UserRef.
func (UserRef) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("oidc_grants", OIDCGrant.Type),
		edge.To("oidc_refresh_tokens", OIDCRefreshToken.Type),
		edge.To("organization_memberships", OrganizationMember.Type),
	}
}
