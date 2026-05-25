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

// OIDCClient holds the schema definition for the OIDCClient entity.
type OIDCClient struct {
	ent.Schema
}

// Fields of the OIDCClient.
func (OIDCClient) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.String("client_id").Unique().Immutable().NotEmpty(),
		field.String("client_name").NotEmpty().MaxLen(64),

		field.Enum("client_type").Values("internal", "official", "public").Default("public"),
		field.Strings("scopes").Default([]string{}).Comment("Allowed scopes for the client."),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("deleted_at").Nillable().Optional(),

		field.Bool("enabled").Default(false),
	}
}

func (OIDCClient) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("enabled", "deleted_at"),
		index.Fields("client_id"),
	}
}

// Edges of the OIDCClient.
func (OIDCClient) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("callback_urls", OIDCCallbackURI.Type),
		edge.To("secrets", OIDCClientSecret.Type),
		edge.To("grants", OIDCGrant.Type),
		edge.To("refresh_tokens", OIDCRefreshToken.Type),
	}
}
