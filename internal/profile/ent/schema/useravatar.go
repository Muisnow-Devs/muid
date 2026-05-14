package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// UserAvatar holds R2 object metadata for a profile avatar.
type UserAvatar struct {
	ent.Schema
}

// Fields of the UserAvatar.
func (UserAvatar) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("object_key").Default(""),
		field.String("content_type").Default(""),
		field.Int64("byte_size").Default(0),
		field.Time("uploaded_at").Optional().Nillable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the UserAvatar.
func (UserAvatar) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserProfile.Type).
			Ref("avatar").
			Field("user_id").
			Unique().
			Required(),
	}
}
