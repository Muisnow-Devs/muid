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

// OIDCRefreshToken holds the schema definition for the OIDCRefreshToken entity.
type OIDCRefreshToken struct {
	ent.Schema
}

func (OIDCRefreshToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("user_id", uuid.UUID{}).Immutable(),
		field.String("client_id").NotEmpty().Immutable(),
		field.Strings("scopes").Optional(),

		field.String("selector").MaxLen(16).Unique().NotEmpty().Immutable(),
		field.Bytes("validation_hash").MaxLen(32).NotEmpty().Immutable(),

		field.UUID("parent_id", uuid.UUID{}).Optional().Immutable(),
		field.UUID("family_id", uuid.UUID{}).Immutable(),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("expires_at").Default(func() time.Time {
			return time.Now().Add(90 * 24 * time.Hour) // Default session expiration of 90 days
		}),
		field.Time("used_at").Optional(),
		field.Time("revoked_at").Optional(),
	}
}

func (OIDCRefreshToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_id"),
		index.Fields("family_id"),
		index.Fields("selector", "revoked_at", "expires_at"),
	}
}

// Edges of the OIDCRefreshToken.
func (OIDCRefreshToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", UserRef.Type).
			Ref("oidc_refresh_tokens").
			Unique().
			Field("user_id").
			Required().
			Immutable(),
		edge.From("parent", OIDCRefreshToken.Type).
			Ref("children").
			Unique().
			Field("parent_id").
			Immutable(),
		edge.To("children", OIDCRefreshToken.Type),
	}
}
