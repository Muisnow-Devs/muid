package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared"
)

// AuditLog is an append-only, immutable record of one state change in this
// service. Rows are INSERTed inside the same transaction as the mutation they
// describe and are never UPDATEd or DELETEd — every field is Immutable() and
// application code must only ever create rows. The contract (action vocabulary,
// change payload encoding) is shared across services in pkg/audit.
type AuditLog struct {
	ent.Schema
}

// Fields of the AuditLog.
func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable().Default(shared.UUIDV7),

		// actor_id is the caller responsible for the change; nil for system
		// or unauthenticated flows.
		field.UUID("actor_id", uuid.UUID{}).Optional().Nillable().Immutable(),

		field.String("action").NotEmpty().Immutable(),
		field.String("resource_type").NotEmpty().Immutable(),
		field.String("resource_id").Immutable(),

		// organization_id scopes org-bound events; nil otherwise.
		field.UUID("organization_id", uuid.UUID{}).Optional().Nillable().Immutable(),

		field.String("trace_id").Optional().Immutable(),

		// changes is the structured JSON change payload; never holds secrets,
		// hashes, tokens, or OTPs.
		field.JSON("changes", json.RawMessage{}).Optional().Immutable(),

		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

// Indexes of the AuditLog.
func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("resource_type", "resource_id"),
		index.Fields("actor_id"),
		index.Fields("organization_id"),
		index.Fields("created_at"),
	}
}
