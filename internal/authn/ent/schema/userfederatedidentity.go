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

// UserFederatedIdentity holds the schema definition for the UserFederatedIdentity entity.
type UserFederatedIdentity struct {
	ent.Schema
}

// Fields of the UserFederatedIdentity.
func (UserFederatedIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("identity_id", uuid.UUID{}).Immutable(),

		field.String("provider").NotEmpty().MaxLen(50).Immutable(),
		field.String("subject").NotEmpty().MaxLen(255).Immutable(),

		field.String("email").Optional().MaxLen(320),
		field.Bool("email_verified").Default(false),
		field.String("display_name").Optional().MaxLen(255),
		field.String("avatar_url").Optional().Nillable(),
		field.String("raw_profile_etag").
			Optional().
			MaxLen(255).
			Comment("Used for profile sync/versioning"),

		field.Time("last_used_at").Optional(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("linked_at").Default(time.Now).Immutable(),
		field.Time("revoked_at").Optional(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (UserFederatedIdentity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "subject").Unique(),
		index.Fields("identity_id"),
		index.Fields("provider"),
		index.Fields("email"),
	}
}

// Edges of the UserFederatedIdentity.
func (UserFederatedIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("identity", UserIdentity.Type).
			Ref("federated_identity").
			Unique().
			Field("identity_id").
			Required().
			Immutable(),
	}
}
