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

// UserAvatar is append-only history for a user's avatar assets (never UPDATE rows to "change" an avatar).
//
// After INSERT, treat user_id, object_key, and content_type as immutable forever (historical asset row);
// application code must not use ent UpdateOne (or SQL UPDATE) to change those columns. New avatar state is
// always a new row (including staging sessions and completed uploads).
//
// Displayed avatar: among rows for this user_id where uploaded_at IS NOT NULL, take the row with the
// greatest id (UUID v7 is time-ordered, so max(id) is deterministic latest completed asset).
// Rows with uploaded_at == nil are in-flight presigned staging uploads only; they are ignored for display.
// Staging-session rows (uploaded_at IS NULL) may be DELETEd when superseded by a newer upload session or
// consumed by completion — only completed rows are append-only history.
//
// Persisted public_url (when set) must be derived from the configured CDN/assets base + object_key at
// insert time, not third-party identity URLs.
type UserAvatar struct {
	ent.Schema
}

// Fields of the UserAvatar.
func (UserAvatar) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable().Default(shared.UUIDV7),
		field.UUID("user_id", uuid.UUID{}).Immutable(),
		field.String("object_key").NotEmpty().Immutable(),
		field.String("content_type").NotEmpty().Immutable(),
		field.Int64("byte_size").Default(0),

		field.String("public_url").
			Optional().
			Nillable().
			Comment("CDN URL persisted at insert when object is in the production assets bucket"),

		// Nil while a staging upload is in progress; set when the row is display-ready (bootstrap or processed asset).
		field.Time("uploaded_at").Optional().Nillable(),
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

// Indexes of the UserAvatar.
func (UserAvatar) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
	}
}

// Edges of the UserAvatar.
func (UserAvatar) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserProfile.Type).
			Ref("avatars").
			Field("user_id").
			Unique().
			Required().
			Immutable(),
	}
}
