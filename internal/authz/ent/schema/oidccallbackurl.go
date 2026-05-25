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

// OIDCCallbackURL holds the schema definition for the OIDCCallbackURL entity.
type OIDCCallbackURL struct {
	ent.Schema
}

// Fields of the OIDCCallbackURL.
func (OIDCCallbackURL) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),
		field.UUID("client_ref_id", uuid.UUID{}).Immutable(),
		field.String("url").NotEmpty().MaxLen(2048).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (OIDCCallbackURL) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_ref_id", "url").Unique(),
	}
}

// Edges of the OIDCCallbackURL.
func (OIDCCallbackURL) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OIDCClient.Type).
			Ref("callback_urls").
			Unique().
			Field("client_ref_id").
			Required().
			Immutable(),
	}
}
