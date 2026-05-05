package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// UserPasskey holds the schema definition for the UserPasskey entity.
type UserPasskey struct {
	ent.Schema
}

// Fields of the UserPasskey.
func (UserPasskey) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),
		field.UUID("user_id", uuid.UUID{}).Immutable(),

		field.Bytes("credential_id").Immutable().NotEmpty().Unique(),
		field.Bytes("public_key").Immutable().NotEmpty(),
		field.String("rp_id").Immutable().NotEmpty(),
		field.Enum("device_type").Values("single_device", "multi_device").Immutable(),

		field.Bool("backup_eligible").Default(false),
		field.Bool("backup_state").Default(false),
		field.Uint32("sign_count").Default(0),

		field.JSON("transports", []string{}).Immutable().Optional(),

		field.Bytes("aaguid").Immutable().Optional(),
		field.String("name").Immutable().MaxLen(255),

		field.Bool("revoked").Default(false),

		field.Time("last_used_at").Optional(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the UserPasskey.
func (UserPasskey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserRef.Type).Ref("passkeys").Unique().Field("user_id").Required().Immutable(),
	}
}
