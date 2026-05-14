package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// UserPreference holds per-profile settings.
type UserPreference struct {
	ent.Schema
}

// Fields of the UserPreference.
func (UserPreference) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable().Default(shared.UUIDV7),
		field.UUID("user_id", uuid.UUID{}).Immutable(),
		field.String("locale").Default("").Comment("BCP-47 locale; empty means server default"),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the UserPreference.
func (UserPreference) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserProfile.Type).
			Ref("preference").
			Field("user_id").
			Unique().
			Required().
			Immutable(),
	}
}
