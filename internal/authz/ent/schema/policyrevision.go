package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// PolicyRevision holds the schema definition for the PolicyRevision entity.
//
// A single row (fixed id 1) tracking the current policy snapshot id. The
// revision UUID changes inside the same transaction as every casbin_rule
// mutation; clients compare it against PolicyChangedEvent.revision_id and
// ListNamespacePoliciesResponse.revision_id to detect stale caches.
type PolicyRevision struct {
	ent.Schema
}

// Fields of the PolicyRevision.
func (PolicyRevision) Fields() []ent.Field {
	return []ent.Field{
		field.Int("id").Unique().Immutable(),

		field.UUID("revision", uuid.UUID{}),

		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}
