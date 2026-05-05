package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// UserSession holds the schema definition for the UserSession entity.
type UserSession struct {
	ent.Schema
}

// Fields of the UserSession.
func (UserSession) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),
		field.UUID("user_id", uuid.UUID{}).Immutable(),

		field.String("selector").NotEmpty().Immutable().MaxLen(32),
		field.Bytes("validator_hash").NotEmpty().Immutable(),

		field.String("ip_address").Optional().Immutable().MaxLen(45),
		field.String("user_agent").Optional().Immutable().MaxLen(512),

		field.Time("last_active_at").Default(time.Now),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("expires_at").Default(func() time.Time {
			return time.Now().Add(7 * 24 * time.Hour)
		}),

		field.Time("revoked_at").Optional(),
	}
}

// Edges of the UserSession.
func (UserSession) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserRef.Type).Ref("sessions").Unique().Field("user_id").Required().Immutable(),
	}
}
