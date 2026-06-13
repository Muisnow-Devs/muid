package core

import (
	"context"

	profileent "sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/pkg/audit"
)

// writeAudit persists one immutable audit record inside the caller's
// transaction, so it commits or rolls back atomically with the audited
// mutation. The actor and trace id are resolved from ctx when the entry omits
// them.
func writeAudit(ctx context.Context, tx *profileent.Tx, e audit.Entry) error {
	if e.TraceID == "" {
		e.TraceID = audit.TraceID(ctx)
	}
	if e.ActorID == nil {
		if id, ok := audit.ActorFromContext(ctx); ok {
			e.ActorID = &id
		}
	}
	create := tx.AuditLog.Create().
		SetNillableActorID(e.ActorID).
		SetAction(e.Action).
		SetResourceType(e.ResourceType).
		SetResourceID(e.ResourceID).
		SetNillableOrganizationID(e.OrganizationID).
		SetTraceID(e.TraceID)
	if e.Changes != nil {
		create = create.SetChanges(e.Changes)
	}
	return create.Exec(ctx)
}
