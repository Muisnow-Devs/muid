package account

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/enttest"
	"sanzi.io/muid/internal/authn/ent/userref"
)

func TestManagerGetMyAccountStatuses(t *testing.T) {
	t.Parallel()

	ctx, db, manager := newTestManager(t, "accountstatuses")
	tests := []struct {
		name      string
		persisted userref.Status
		expected  Status
	}{
		{name: "active", persisted: userref.StatusActive, expected: StatusActive},
		{name: "disabled", persisted: userref.StatusDisabled, expected: StatusDisabled},
		{
			name:      "pending deletion",
			persisted: userref.StatusPendingDeletion,
			expected:  StatusPendingDeletion,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userID := createUser(t, ctx, db, tc.persisted)
			createEmail(t, ctx, db, userID, true, false)

			snapshot, err := manager.GetMyAccount(ctx, userID)
			if err != nil {
				t.Fatalf("GetMyAccount: %v", err)
			}
			if snapshot.Status != tc.expected {
				t.Errorf("status = %q, want %q", snapshot.Status, tc.expected)
			}
		})
	}
}

func TestManagerGetMyAccountPrimaryEmailInvariants(t *testing.T) {
	t.Parallel()

	ctx, db, manager := newTestManager(t, "accountprimary")
	tests := []struct {
		name  string
		setup func(uuid.UUID)
		want  error
	}{
		{
			name:  "missing user",
			setup: func(uuid.UUID) {},
			want:  ErrNotFound,
		},
		{
			name: "zero primary emails",
			setup: func(userID uuid.UUID) {
				createEmail(t, ctx, db, userID, false, false)
			},
			want: ErrInvalidState,
		},
		{
			name: "revoked primary email identity",
			setup: func(userID uuid.UUID) {
				identity := createEmail(t, ctx, db, userID, true, false)
				err := db.UserIdentity.UpdateOneID(identity.ID).SetRevokedAt(time.Now()).Exec(ctx)
				if err != nil {
					t.Fatalf("revoke email identity: %v", err)
				}
			},
			want: ErrInvalidState,
		},
		{
			name: "multiple primary emails",
			setup: func(userID uuid.UUID) {
				createEmail(t, ctx, db, userID, true, false)
				createEmail(t, ctx, db, userID, true, false)
			},
			want: ErrInvalidState,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userID := uuid.New()
			if tc.name != "missing user" {
				userID = createUser(t, ctx, db, userref.StatusActive)
			}
			tc.setup(userID)

			_, err := manager.GetMyAccount(ctx, userID)
			if !errors.Is(err, tc.want) {
				t.Errorf("GetMyAccount error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestManagerGetMyAccountRejectsUnknownStatus(t *testing.T) {
	t.Parallel()

	ctx, db, manager := newTestManager(t, "accountunknownstatus")
	userID := createUser(t, ctx, db, userref.StatusActive)
	createEmail(t, ctx, db, userID, true, false)

	rawDB, err := sql.Open("sqlite3", "file:accountunknownstatus?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("open raw database: %v", err)
	}
	t.Cleanup(func() { rawDB.Close() })

	_, err = rawDB.ExecContext(ctx, "UPDATE user_refs SET status = ? WHERE id = ?", "unknown", userID.String())
	if err != nil {
		t.Fatalf("set unknown status: %v", err)
	}

	_, err = manager.GetMyAccount(ctx, userID)
	if !errors.Is(err, ErrInvalidState) {
		t.Errorf("GetMyAccount error = %v, want %v", err, ErrInvalidState)
	}
}

func TestManagerGetMyAccountRejectsInvalidPrimaryEmailIdentity(t *testing.T) {
	t.Parallel()

	ctx, db, manager := newTestManager(t, "accountprimaryidentity")
	tests := []struct {
		name  string
		setup func(userID uuid.UUID)
	}{
		{
			name: "parent belongs to another user",
			setup: func(userID uuid.UUID) {
				otherUserID := createUser(t, ctx, db, userref.StatusActive)
				createEmailWithParent(t, ctx, db, userID, otherUserID, "email", "", true, false)
			},
		},
		{
			name: "parent provider is not email",
			setup: func(userID uuid.UUID) {
				createEmailWithParent(t, ctx, db, userID, userID, "password", "", true, false)
			},
		},
		{
			name: "parent subject does not match email",
			setup: func(userID uuid.UUID) {
				createEmailWithParent(t, ctx, db, userID, userID, "email", "different@example.test", true, false)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userID := createUser(t, ctx, db, userref.StatusActive)
			tc.setup(userID)

			_, err := manager.GetMyAccount(ctx, userID)
			if !errors.Is(err, ErrInvalidState) {
				t.Errorf("GetMyAccount error = %v, want %v", err, ErrInvalidState)
			}
		})
	}
}

func TestManagerGetMyAccountFiltersAndOrdersLinkedIdentities(t *testing.T) {
	t.Parallel()

	ctx, db, manager := newTestManager(t, "accountidentities")
	userID := createUser(t, ctx, db, userref.StatusActive)
	createEmail(t, ctx, db, userID, true, false)

	base := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC)
	createFederated(t, ctx, db, userID, "github", "github", base.Add(time.Hour), false, false)
	createFederated(t, ctx, db, userID, "apple", "apple", base.Add(2*time.Hour), false, false)
	createFederated(t, ctx, db, userID, "apple", "apple", base, false, false)
	createFederated(t, ctx, db, userID, "revoked-child", "revoked-child", base, false, true)
	createFederated(t, ctx, db, userID, "revoked-parent", "revoked-parent", base, true, false)

	snapshot, err := manager.GetMyAccount(ctx, userID)
	if err != nil {
		t.Fatalf("GetMyAccount: %v", err)
	}
	want := []LinkedIdentity{
		{Provider: "apple", LinkedAt: base},
		{Provider: "apple", LinkedAt: base.Add(2 * time.Hour)},
		{Provider: "github", LinkedAt: base.Add(time.Hour)},
	}
	if !reflect.DeepEqual(snapshot.LinkedIdentities, want) {
		t.Errorf("linked identities = %#v, want %#v", snapshot.LinkedIdentities, want)
	}
}

func TestManagerGetMyAccountRejectsProviderMismatch(t *testing.T) {
	t.Parallel()

	ctx, db, manager := newTestManager(t, "accountprovidermismatch")
	userID := createUser(t, ctx, db, userref.StatusActive)
	createEmail(t, ctx, db, userID, true, false)
	createFederated(t, ctx, db, userID, "identity-provider", "federated-provider", time.Now(), false, false)

	_, err := manager.GetMyAccount(ctx, userID)
	if !errors.Is(err, ErrInvalidState) {
		t.Errorf("GetMyAccount error = %v, want %v", err, ErrInvalidState)
	}
}

func TestSnapshotExposesOnlyAccountFields(t *testing.T) {
	t.Parallel()

	typeOfSnapshot := reflect.TypeOf(Snapshot{})
	want := []string{"Status", "PrimaryEmail", "CreatedAt", "LinkedIdentities"}
	if typeOfSnapshot.NumField() != len(want) {
		t.Fatalf("Snapshot has %d fields, want %d", typeOfSnapshot.NumField(), len(want))
	}
	for i, name := range want {
		if got := typeOfSnapshot.Field(i).Name; got != name {
			t.Errorf("Snapshot field %d = %q, want %q", i, got, name)
		}
	}

	typeOfLinked := reflect.TypeOf(LinkedIdentity{})
	if typeOfLinked.NumField() != 2 {
		t.Fatalf("LinkedIdentity has %d fields, want 2", typeOfLinked.NumField())
	}
	if got := typeOfLinked.Field(0).Name; got != "Provider" {
		t.Errorf("LinkedIdentity field 0 = %q, want Provider", got)
	}
	if got := typeOfLinked.Field(1).Name; got != "LinkedAt" {
		t.Errorf("LinkedIdentity field 1 = %q, want LinkedAt", got)
	}
}

func newTestManager(t *testing.T, databaseName string) (context.Context, *authnent.Client, *Manager) {
	t.Helper()

	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+databaseName+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { db.Close() })
	return ctx, db, NewManager(db)
}

func createUser(t *testing.T, ctx context.Context, db *authnent.Client, status userref.Status) uuid.UUID {
	t.Helper()

	userID := uuid.New()
	err := db.UserRef.Create().SetID(userID).SetStatus(status).Exec(ctx)
	if err != nil {
		t.Fatalf("create user ref: %v", err)
	}
	return userID
}

func createEmail(
	t *testing.T,
	ctx context.Context,
	db *authnent.Client,
	userID uuid.UUID,
	isPrimary bool,
	revoked bool,
) *authnent.UserIdentity {
	t.Helper()

	return createEmailWithParent(t, ctx, db, userID, userID, "email", "", isPrimary, revoked)
}

func createEmailWithParent(
	t *testing.T,
	ctx context.Context,
	db *authnent.Client,
	userID uuid.UUID,
	parentUserID uuid.UUID,
	provider string,
	subject string,
	isPrimary bool,
	revoked bool,
) *authnent.UserIdentity {
	t.Helper()

	email := uuid.NewString() + "@example.test"
	if subject == "" {
		subject = email
	}
	identity, err := db.UserIdentity.Create().
		SetUserID(parentUserID).
		SetProvider(provider).
		SetSubject(subject).
		Save(ctx)
	if err != nil {
		t.Fatalf("create email identity: %v", err)
	}

	create := db.UserEmail.Create().
		SetID(uuid.New()).
		SetIdentityID(identity.ID).
		SetUserID(userID).
		SetEmail(email).
		SetIsPrimary(isPrimary)
	if revoked {
		create.SetRevokedAt(time.Now())
	}
	if err := create.Exec(ctx); err != nil {
		t.Fatalf("create user email: %v", err)
	}
	return identity
}

func createFederated(
	t *testing.T,
	ctx context.Context,
	db *authnent.Client,
	userID uuid.UUID,
	identityProvider string,
	federatedProvider string,
	linkedAt time.Time,
	parentRevoked bool,
	childRevoked bool,
) {
	t.Helper()

	createIdentity := db.UserIdentity.Create().
		SetUserID(userID).
		SetProvider(identityProvider).
		SetSubject(uuid.NewString())
	if parentRevoked {
		createIdentity.SetRevokedAt(time.Now())
	}
	identity, err := createIdentity.Save(ctx)
	if err != nil {
		t.Fatalf("create federated parent identity: %v", err)
	}

	createFederated := db.UserFederatedIdentity.Create().
		SetIdentityID(identity.ID).
		SetProvider(federatedProvider).
		SetSubject(uuid.NewString()).
		SetLinkedAt(linkedAt)
	if childRevoked {
		createFederated.SetRevokedAt(time.Now())
	}
	if err := createFederated.Exec(ctx); err != nil {
		t.Fatalf("create federated identity: %v", err)
	}
}
