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
	"sanzi.io/muid/pkg/validation"
)

// UserProfile holds the schema definition for the UserProfile entity.
// Avatar URLs are not stored here; see UserAvatar rows for the same user_id.
type UserProfile struct {
	ent.Schema
}

// Fields of the UserProfile.
func (UserProfile) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable().Default(shared.UUIDV7),
		field.String("email_ref").NotEmpty().Unique(),
		field.String("display_name").NotEmpty(),
		field.String("username").NotEmpty().Unique().Validate(validation.CheckUsername),

		field.String("locale").Default("en").Comment("BCP-47 locale; empty means server default"),
		field.String("timezone").
			Default("UTC").
			MaxLen(64).
			Comment("IANA time zone; empty means UTC for mail display"),
		field.String("biography").Default("").MaxLen(1024),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Indexes of the UserProfile.
func (UserProfile) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email_ref"),
		index.Fields("username"),
	}
}

// Edges of the UserProfile.
func (UserProfile) Edges() []ent.Edge {
	return []ent.Edge{
		// One profile has many UserAvatar rows (upload history). Canonical URL is resolved from
		// the latest eligible row; see profilegrpc / UserAvatar schema comments.
		edge.To("avatars", UserAvatar.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("original_identity", UserOriginalIdentity.Type).
			Unique().
			Immutable().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
