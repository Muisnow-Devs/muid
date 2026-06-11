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

// OIDCClientAccessGrant is the per-user allowlist for clients with the
// "private" access policy. Rows are hard-deleted when access is removed.
type OIDCClientAccessGrant struct {
	ent.Schema
}

// Fields of the OIDCClientAccessGrant.
func (OIDCClientAccessGrant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.UUID("client_ref_id", uuid.UUID{}).Immutable(),
		field.UUID("user_id", uuid.UUID{}).Immutable(),
		field.UUID("granted_by", uuid.UUID{}).Optional().Immutable(),

		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (OIDCClientAccessGrant) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_ref_id", "user_id").Unique(),
		index.Fields("user_id"),
	}
}

// Edges of the OIDCClientAccessGrant.
func (OIDCClientAccessGrant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OIDCClient.Type).
			Ref("access_grants").
			Unique().
			Field("client_ref_id").
			Required().
			Immutable(),
		edge.From("user", UserRef.Type).
			Ref("oidc_access_grants").
			Unique().
			Field("user_id").
			Required().
			Immutable(),
	}
}
