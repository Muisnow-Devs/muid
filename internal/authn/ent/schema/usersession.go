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

// UserSession holds the schema definition for the UserSession entity.
type UserSession struct {
	ent.Schema
}

// Fields of the UserSession.
func (UserSession) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),
		field.UUID("user_id", uuid.UUID{}).Immutable(),

		// Selector should be a random bytes. It is used to look up the session without revealing the actual session ID (which is the validator).
		// DON'T CHANGE THIS TO HEX. THIS IS NOT THE MAIN POINT.
		field.Bytes("selector").MaxLen(16).NotEmpty().Immutable(),
		field.Bytes("validator_hash").MaxLen(32).NotEmpty().Immutable(),

		field.String("ip_address").Optional().Immutable().MaxLen(45),
		field.String("user_agent").Optional().Immutable().MaxLen(512),
		field.String("device_name").Optional().Immutable().MaxLen(255),

		field.Time("last_active_at").Default(time.Now),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("expires_at").Default(func() time.Time {
			return time.Now().Add(7 * 24 * time.Hour)
		}),

		field.Time("revoked_at").Optional(),
	}
}

func (UserSession) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("selector").Unique(),
		index.Fields("user_id"),
	}
}

// Edges of the UserSession.
func (UserSession) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserRef.Type).
			Ref("sessions").
			Unique().
			Field("user_id").
			Required().
			Immutable(),
	}
}
