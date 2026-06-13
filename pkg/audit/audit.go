// Package audit defines the service-agnostic contract for immutable audit
// records. Each service declares its own append-only AuditLog Ent table (Ent
// codegen is per-service), but the record shape, the action vocabulary, the
// change-payload encoding, and the actor/trace context plumbing live here so
// every service emits audit entries the same way.
//
// Audit rows are written inside the same transaction as the mutation they
// describe (see each service's writeAudit helper), so a record can never
// outlive a rolled-back change nor a change escape unrecorded.
package audit

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"sanzi.io/muid/pkg/log"
)

// Entry is the canonical audit record a service builds before persisting it
// through its own AuditLog table. Zero-value optional fields (nil ActorID /
// OrganizationID, empty TraceID / Changes) are valid and persisted as NULL.
type Entry struct {
	// ActorID is the caller who made the change; nil for system or
	// unauthenticated flows. Resolved from context by writeAudit when unset.
	ActorID *uuid.UUID
	// Action is a stable "<resource>.<verb>" identifier (see actions.go).
	Action string
	// ResourceType and ResourceID identify the entity that changed.
	ResourceType string
	ResourceID   string
	// OrganizationID scopes org-bound events; nil otherwise.
	OrganizationID *uuid.UUID
	// TraceID correlates the entry with the originating request; resolved
	// from context by writeAudit when empty.
	TraceID string
	// Changes is the structured JSON change payload (see Changes); never
	// carries secrets, hashes, tokens, or OTPs.
	Changes json.RawMessage
}

// Changes marshals a before/after pair into a stable JSON object for the
// changes column. Pass nil for before on a create or nil for after on a
// delete. encoding/json sorts struct/map keys, so the output is
// deterministic. Marshal failures yield nil (the change payload is best
// effort and never blocks the audited mutation).
func Changes(before, after any) json.RawMessage {
	payload := struct {
		Before any `json:"before,omitempty"`
		After  any `json:"after,omitempty"`
	}{Before: before, After: after}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return raw
}

// Payload marshals a single value into the changes column for events that are
// not naturally before/after shaped (e.g. a revocation reason). Marshal
// failures yield nil.
func Payload(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

// TraceID returns the request trace id carried on ctx, or "" when absent.
func TraceID(ctx context.Context) string {
	id, _ := log.FromContext(ctx)
	return id
}
