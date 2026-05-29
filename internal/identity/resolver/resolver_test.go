package resolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent/enttest"
	"sanzi.io/muid/internal/authn/ent/useremail"
	"sanzi.io/muid/pkg/shared"
)

type mockProfileServiceClient struct {
	profilepb.ProfileServiceClient
	createdID string
	err       error
}

func (m *mockProfileServiceClient) CreateProfile(
	ctx context.Context,
	in *profilepb.CreateProfileRequest,
	opts ...grpc.CallOption,
) (*profilepb.CreateProfileResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	resp := &profilepb.CreateProfileResponse{}
	resp.SetId(m.createdID)
	return resp, nil
}

func TestEntUserResolver_ResolveUser(t *testing.T) {
	t.Parallel()

	client := enttest.Open(t, "sqlite3", "file:entresolver?mode=memory&cache=shared&_fk=1")
	defer client.Close()

	ctx := context.Background()

	// 1. Test existing user reference — seed via UserRef + UserEmail (email lives in UserEmail now)
	existingID := uuid.New()
	email := "existing@example.com"

	err := client.UserRef.Create().SetID(existingID).Exec(ctx)
	if err != nil {
		t.Fatalf("failed to seed userref: %v", err)
	}

	// Create the UserIdentity and UserEmail rows that ResolveUser looks up.
	identityRow, err := client.UserIdentity.Create().
		SetUserID(existingID).
		SetProvider("email").
		SetSubject(email).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to seed useridentity: %v", err)
	}
	err = client.UserEmail.Create().
		SetID(shared.UUIDV7()).
		SetIdentityID(identityRow.ID).
		SetUserID(existingID).
		SetEmail(email).
		SetIsPrimary(true).
		Exec(ctx)
	if err != nil {
		t.Fatalf("failed to seed useremail: %v", err)
	}

	mockCli := &mockProfileServiceClient{
		createdID: uuid.New().String(),
	}

	r := NewEntUserResolver(client, mockCli, 2*time.Second)

	claimsInfo := &claims.IdentityInformation{}
	claimsInfo.SetEmail(email)

	res, err := r.ResolveUser(ctx, claimsInfo)
	if err != nil {
		t.Fatalf("unexpected error resolving existing user: %v", err)
	}
	if res.UserID != existingID {
		t.Errorf("expected UserID %v, got %v", existingID, res.UserID)
	}
	if res.Created {
		t.Error("expected Created to be false")
	}
	if !res.Existing {
		t.Error("expected Existing to be true")
	}

	// 2. Test new user creation - success case
	newEmail := "new@example.com"
	newID := uuid.New()
	mockCli2 := &mockProfileServiceClient{
		createdID: newID.String(),
	}
	r2 := NewEntUserResolver(client, mockCli2, 2*time.Second)

	newClaims := &claims.IdentityInformation{}
	newClaims.SetEmail(newEmail)

	res2, err := r2.ResolveUser(ctx, newClaims)
	if err != nil {
		t.Fatalf("unexpected error resolving new user: %v", err)
	}
	if res2.UserID != newID {
		t.Errorf("expected UserID %v, got %v", newID, res2.UserID)
	}
	if !res2.Created {
		t.Error("expected Created to be true")
	}
	if res2.Existing {
		t.Error("expected Existing to be false")
	}

	// Verify the UserRef record was saved (email is NOT on UserRef any more).
	saved, err := client.UserRef.Get(ctx, newID)
	if err != nil {
		t.Fatalf("failed to query new userref: %v", err)
	}
	if saved.ID != newID {
		t.Errorf("expected saved UserRef ID to be %v, got %v", newID, saved.ID)
	}
	// No UserEmail row is expected here: the resolver only creates UserRef.
	// UserEmail is created later by email_store.LinkIdentity in the auth flow.
	hasEmail, err := client.UserEmail.Query().
		Where(useremail.UserIDEQ(newID)).
		Exist(ctx)
	if err != nil {
		t.Fatalf("failed to query useremail: %v", err)
	}
	if hasEmail {
		t.Error("expected no UserEmail row for resolver-created user (LinkIdentity creates it)")
	}

	// 3. Test new user creation - profile service error
	errEmail := "err@example.com"
	mockCliErr := &mockProfileServiceClient{
		err: errors.New("profile creation failed"),
	}
	r3 := NewEntUserResolver(client, mockCliErr, 2*time.Second)

	errClaims := &claims.IdentityInformation{}
	errClaims.SetEmail(errEmail)

	_, err = r3.ResolveUser(ctx, errClaims)
	if err == nil {
		t.Fatal("expected error from ResolveUser, got nil")
	}
	if err.Error() != "profile creation failed" {
		t.Errorf("expected 'profile creation failed' error, got %v", err)
	}
}
