// Package authnaudit writes immutable audit records for authn mutations. It
// lives apart from the oidc and grpc handler packages because both emit audit
// entries, and apart from pkg/audit because the AuditLog Ent table is
// authn-specific (Ent codegen is per service).
package authnaudit

import (
	"context"

	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/pkg/audit"
)

// Write persists one immutable audit record inside the caller's transaction,
// so it commits or rolls back atomically with the audited mutation. The actor
// and trace id are resolved from ctx when the entry omits them.
func Write(ctx context.Context, tx *authnent.Tx, e audit.Entry) error {
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
