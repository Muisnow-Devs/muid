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

// TODO: Add organization specific clients in the future, with a reference to the organization and additional fields as needed.

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
		field.UUID("owner_organization_id", uuid.UUID{}),

		field.Strings("scopes").Default([]string{}).Comment("Allowed scopes for the client."),

		field.Enum("token_endpoint_auth_method").
			Values(
				"none",
				"client_secret_basic",
				"client_secret_post",
				"private_key_jwt",
			).
			Default("none"),

		field.Enum("application_type").
			Values("web", "native").
			Default("web"),
		field.Enum("access_policy").
			Values("public", "organization", "private").
			Default("private").
			Comment("public is public accessible, organization is accessible to members of the owning organization, private is only accessible to specific users or groups."),

		field.Enum("verification_status").
			Values("unverified", "pending", "verified", "official", "rejected").
			Default("unverified"),
		field.Enum("publish_status").
			Values("draft", "testing", "published", "disabled").
			Default("draft"),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("deleted_at").Nillable().Optional(),
	}
}

func (OIDCClient) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_id"),
		index.Fields("owner_organization_id"),
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
