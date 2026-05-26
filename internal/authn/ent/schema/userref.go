package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
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
		field.String("email").NotEmpty().Unique(),

		field.Time("last_login_at").Optional(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (UserRef) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email"),
	}
}

// Edges of the UserRef.
func (UserRef) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("sessions", UserSession.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("passkeys", UserPasskey.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("federated_identities", UserFederatedIdentity.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
