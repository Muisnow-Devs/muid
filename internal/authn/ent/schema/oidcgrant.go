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

// OIDCGrant holds the schema definition for the OIDCGrant entity.
type OIDCGrant struct {
	ent.Schema
}

// Fields of the OIDCGrant.
func (OIDCGrant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("user_id", uuid.UUID{}).Immutable(),
		field.UUID("client_ref_id", uuid.UUID{}).Immutable(),

		field.Strings("scopes").Default([]string{}),
		field.Time("last_used_at").Optional(),

		field.Time("revoked_at").Optional(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("authorized_at").Default(time.Now).Immutable(),
	}
}

func (OIDCGrant) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_ref_id").Unique(),
		index.Fields("client_ref_id", "revoked_at"),
	}
}

// Edges of the OIDCGrant.
func (OIDCGrant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserRef.Type).
			Ref("grants").
			Unique().
			Field("user_id").
			Required().
			Immutable(),
		edge.From("client", OIDCClient.Type).
			Ref("grants").
			Unique().
			Field("client_ref_id").
			Required().
			Immutable(),
	}
}
