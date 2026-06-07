package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
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

		field.Time("last_login_at").Optional(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the UserRef.
func (UserRef) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("sessions", UserSession.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("identities", UserIdentity.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("emails", UserEmail.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("grants", OIDCGrant.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("oidc_refresh_tokens", OIDCRefreshToken.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
