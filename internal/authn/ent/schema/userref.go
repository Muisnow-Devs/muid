package schema

import (
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
		field.String("username").Optional().Unique(),
		field.String("email").NotEmpty().Unique(),
	}
}

// Edges of the UserRef.
func (UserRef) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("sessions", UserSession.Type),
		edge.To("passkeys", UserPasskey.Type),
		edge.To("oidc_refresh_tokens", OIDCRefreshToken.Type),
	}
}
