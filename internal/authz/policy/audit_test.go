package policy

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authz/ent/auditlog"
	"sanzi.io/muid/pkg/audit"
)

// TestCreateOrganizationWritesAudit verifies a successful mutation emits one
// structured audit row in the same transaction.
func TestCreateOrganizationWritesAudit(t *testing.T) {
	m, client, _ := newTestManager(t, "authzauditcreate")
	ctx := context.Background()

	owner := uuid.New()
	orgID, err := m.CreateOrganization(ctx, "Acme", "desc", owner)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}

	rows, err := client.AuditLog.Query().
		Where(auditlog.Action(audit.ActionOrganizationCreate)).
		All(ctx)
	if err != nil {
		t.Fatalf("query audit rows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.ResourceType != audit.ResourceOrganization {
		t.Errorf("resource_type = %q, want %q", row.ResourceType, audit.ResourceOrganization)
	}
	if row.ResourceID != orgID.String() {
		t.Errorf("resource_id = %q, want %q", row.ResourceID, orgID)
	}
	if row.OrganizationID == nil || *row.OrganizationID != orgID {
		t.Errorf("organization_id = %v, want %v", row.OrganizationID, orgID)
	}
	if row.CreatedAt.IsZero() {
		t.Error("created_at is zero")
	}
	if len(row.Changes) == 0 {
		t.Error("changes payload is empty")
	}
}

// TestAuditRollsBackWithTransaction proves the audit row participates in the
// surrounding transaction: rolling back discards it, so a record can never
// outlive a rolled-back change.
func TestAuditRollsBackWithTransaction(t *testing.T) {
	_, client, _ := newTestManager(t, "authzauditrollback")
	ctx := context.Background()

	tx, err := client.Tx(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	orgID := uuid.New()
	err = writeAudit(ctx, tx, audit.Entry{
		Action:         audit.ActionOrganizationCreate,
		ResourceType:   audit.ResourceOrganization,
		ResourceID:     orgID.String(),
		OrganizationID: &orgID,
		Changes:        audit.Changes(nil, map[string]any{"name": "Acme"}),
	})
	if err != nil {
		t.Fatalf("writeAudit() error = %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	count, err := client.AuditLog.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("audit rows after rollback = %d, want 0", count)
	}
}

// TestFailedMutationWritesNoAudit verifies a mutation that errors leaves no
// audit row behind (here a duplicate membership).
func TestFailedMutationWritesNoAudit(t *testing.T) {
	m, client, _ := newTestManager(t, "authzauditfail")
	ctx := context.Background()

	owner := uuid.New()
	orgID, err := m.CreateOrganization(ctx, "Acme", "", owner)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}

	member := uuid.New()
	err = m.AddMember(ctx, uuid.Nil, orgID, member, "member")
	if err != nil {
		t.Fatalf("AddMember() error = %v", err)
	}

	countAfterFirst, err := client.AuditLog.Query().
		Where(auditlog.Action(audit.ActionMemberAdd)).
		Count(ctx)
	if err != nil {
		t.Fatalf("count member.add rows: %v", err)
	}
	if countAfterFirst != 1 {
		t.Fatalf("member.add audit rows = %d, want 1", countAfterFirst)
	}

	// Adding the same member again must fail and write no further audit row.
	err = m.AddMember(ctx, uuid.Nil, orgID, member, "member")
	if err == nil {
		t.Fatal("AddMember() duplicate expected error, got nil")
	}
	countAfterDup, err := client.AuditLog.Query().
		Where(auditlog.Action(audit.ActionMemberAdd)).
		Count(ctx)
	if err != nil {
		t.Fatalf("count member.add rows: %v", err)
	}
	if countAfterDup != 1 {
		t.Fatalf("member.add audit rows after duplicate = %d, want 1", countAfterDup)
	}
}
