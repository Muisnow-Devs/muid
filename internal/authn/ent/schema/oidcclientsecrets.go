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

// OIDCClientSecret holds the schema definition for the OIDCClientSecret entity.
type OIDCClientSecret struct {
	ent.Schema
}

// Fields of the OIDCClientSecret.
func (OIDCClientSecret) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),
		field.UUID("client_ref_id", uuid.UUID{}).Immutable(),

		field.Bytes("secret_hash").Sensitive().NotEmpty().MaxLen(32).Immutable(),
		field.String("hint").NotEmpty().MaxLen(64).Immutable(),

		field.Time("last_used_at").Nillable().Optional(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("expires_at").Nillable().Optional(),
		field.Time("revoked_at").Nillable().Optional(),
	}
}

func (OIDCClientSecret) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_ref_id", "revoked_at"),
		index.Fields("client_ref_id", "secret_hash").Unique(),
	}
}

// Edges of the OIDCClientSecret.
func (OIDCClientSecret) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OIDCClient.Type).
			Ref("secrets").
			Unique().
			Field("client_ref_id").
			Required().
			Immutable(),
	}
}
