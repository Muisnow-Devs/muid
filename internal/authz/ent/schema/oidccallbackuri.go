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

// OIDCCallbackURI holds the schema definition for the OIDCCallbackURI entity.
type OIDCCallbackURI struct {
	ent.Schema
}

// Fields of the OIDCCallbackURI.
func (OIDCCallbackURI) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),
		field.UUID("client_ref_id", uuid.UUID{}).Immutable(),

		field.String("uri").NotEmpty().MaxLen(2048).Immutable(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (OIDCCallbackURI) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_ref_id", "uri").Unique(),
	}
}

// Edges of the OIDCCallbackURI.
func (OIDCCallbackURI) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OIDCClient.Type).
			Ref("callback_urls").
			Unique().
			Field("client_ref_id").
			Required().
			Immutable(),
	}
}
