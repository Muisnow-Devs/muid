package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// CasbinRule holds the schema definition for the CasbinRule entity.
//
// Each row is one casbin rule (see pkg/shared/authzmodel for the model):
//
//	p, <subject>, <domain>, <object>, <action>  — permission grant
//	g, <member>, <role>, <domain>               — role link / membership
//
// Subjects are "user:<uuid>" or "role:<name>"; the domain is an organization
// UUID or "*" for rules seeded from the static policy configuration. This
// table replaces the former RolePermission table and is written exclusively
// by internal/authz/policy.
type CasbinRule struct {
	ent.Schema
}

// Fields of the CasbinRule.
func (CasbinRule) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(shared.UUIDV7).Immutable(),

		field.String("ptype").NotEmpty().MaxLen(8),

		field.String("v0").Default("").MaxLen(256),
		field.String("v1").Default("").MaxLen(256),
		field.String("v2").Default("").MaxLen(256),
		field.String("v3").Default("").MaxLen(256),
		field.String("v4").Default("").MaxLen(256),
		field.String("v5").Default("").MaxLen(256),

		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (CasbinRule) Indexes() []ent.Index {
	return []ent.Index{
		// The same rule cannot be stored twice.
		index.Fields("ptype", "v0", "v1", "v2", "v3", "v4", "v5").Unique(),
		// p-rules by domain (v1) and object (v2, namespace-prefix scans);
		// g-rules by role (v1) and domain (v2).
		index.Fields("ptype", "v1"),
		index.Fields("ptype", "v2"),
		// g-rules by member subject (v0): per-user membership lookups.
		index.Fields("ptype", "v0"),
	}
}
