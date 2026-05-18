package schema

// This is for backwards compatibility with the old MuID system identity.
// Shouldn't be used for anything new, and might eventually be removed after all users have been migrated to the new system identity.

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// UserOriginalIdentity holds the schema definition for the UserOriginalIdentity entity.
type UserOriginalIdentity struct {
	ent.Schema
}

// Fields of the UserOriginalIdentity.
func (UserOriginalIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.String("original_identity").NotEmpty().Immutable().Unique(),
	}
}

// Edges of the UserOriginalIdentity.
func (UserOriginalIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("user", UserProfile.Type).Unique().Immutable().Required(),
	}
}
