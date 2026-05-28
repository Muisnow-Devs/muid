package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// UserIdentity holds the schema definition for the UserIdentity entity.
type UserIdentity struct {
	ent.Schema
}

// Fields of the UserIdentity.
func (UserIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("user_id", uuid.UUID{}).Immutable(),

		field.String("provider").NotEmpty(),
		field.String("subject").NotEmpty(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("revoked_at").Optional(),
	}
}

func (UserIdentity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "provider", "subject").Unique(),
		index.Fields("provider", "subject", "revoked_at"),
	}
}

// Edges of the UserIdentity.
func (UserIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserRef.Type).
			Ref("identities").
			Unique().
			Field("user_id").
			Required().
			Immutable(),
		edge.To("passkey_identity", UserPasskey.Type).
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("federated_identity", UserFederatedIdentity.Type).
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
