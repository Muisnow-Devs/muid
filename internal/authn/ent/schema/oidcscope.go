package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OIDCScope holds the schema definition for the OIDCScope entity.
//
// The primary key is the scope identifier itself (e.g. "organization:write"),
// following the OAuth 2.0 / OIDC convention of human-readable scope strings.
// Name and description are stored alongside the identifier; description supports
// i18n via a JSON map keyed by BCP-47 language tags (e.g. {"en": "…", "zh-TW": "…"}).
type OIDCScope struct {
	ent.Schema
}

// Fields of the OIDCScope.
func (OIDCScope) Fields() []ent.Field {
	return []ent.Field{
		// id is the scope string itself, e.g. "openid", "profile", "organization:write".
		field.String("id").
			NotEmpty().
			MaxLen(128).
			Immutable().
			Comment("Scope identifier used in OAuth 2.0 / OIDC requests, e.g. \"organization:write\"."),

		field.String("name").
			NotEmpty().
			MaxLen(128).
			Comment("Short human-readable display name for the scope."),

		// description is stored as a JSON object keyed by BCP-47 language tags.
		// Example: {"en": "Write access to organizations", "zh-TW": "組織寫入權限"}
		// Use Optional so scopes can be registered without a description initially.
		field.JSON("description", map[string]string{}).
			Optional().
			Comment("i18n description map keyed by BCP-47 language tag (e.g. \"en\", \"zh-TW\")."),
	}
}

func (OIDCScope) Indexes() []ent.Index {
	return []ent.Index{
		// The string id is already the PK; index on name for admin lookups.
		index.Fields("name"),
	}
}

// Edges of the OIDCScope.
func (OIDCScope) Edges() []ent.Edge {
	return nil
}
