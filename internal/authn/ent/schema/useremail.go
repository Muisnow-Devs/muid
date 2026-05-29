package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// UserEmail holds the schema definition for the UserEmail entity.
type UserEmail struct {
	ent.Schema
}

// Fields of the UserEmail.
func (UserEmail) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable(),

		field.UUID("identity_id", uuid.UUID{}).Immutable(),

		field.UUID("user_id", uuid.UUID{}).Immutable(),
		field.String("email").Unique().Immutable().MaxLen(254),
		field.Bool("is_primary").Default(false),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("revoked_at").Optional().Immutable(),
	}
}

func (UserEmail) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("identity_id"),
		index.Fields("user_id", "email").Unique(),
		index.Fields("user_id", "is_primary"),
		index.Fields("email"),
	}
}

// Edges of the UserEmail.
func (UserEmail) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserRef.Type).
			Ref("emails").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
		edge.From("identity", UserIdentity.Type).
			Ref("email_identity").
			Unique().
			Field("identity_id").
			Required().
			Immutable(),
	}
}
