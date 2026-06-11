package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/enttest"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/oidc/policy"
)

type stubPermissions bool

func (s stubPermissions) HasPermission(
	context.Context,
	uuid.UUID,
	uuid.UUID,
	string,
) (bool, error) {
	return bool(s), nil
}

func newAdminFixture(
	t *testing.T,
	dbName string,
	allowed bool,
) (context.Context, *Admin, *ent.Client) {
	t.Helper()

	db := enttest.Open(t, "sqlite3", "file:"+dbName+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { db.Close() })
	return context.Background(), NewAdmin(db, stubPermissions(allowed)), db
}

func TestAdminClientLifecycle(t *testing.T) {
	t.Parallel()

	ctx, admin, db := newAdminFixture(t, "oidcadmin", true)
	actor := uuid.New()
	organizationID := uuid.New()

	client, err := admin.CreateClient(ctx, actor, CreateClientInput{
		OrganizationID:  organizationID,
		ClientName:      "My App",
		ApplicationType: oidcclient.ApplicationTypeWeb,
		AccessPolicy:    oidcclient.AccessPolicyOrganization,
		Scopes:          []string{ScopeOpenID, ScopeEmail},
		RedirectURIs:    []string{"https://app.test/cb"},
		GrantTypes:      []string{policy.GrantTypeAuthorizationCode, policy.GrantTypeRefreshToken},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if client.ClientID == "" ||
		client.TokenEndpointAuthMethod != oidcclient.TokenEndpointAuthMethodNone {
		t.Fatalf("client = %+v, want generated client_id with auth method none", client)
	}
	if len(client.Edges.CallbackUrls) != 1 {
		t.Fatalf("redirect uris = %d, want 1", len(client.Edges.CallbackUrls))
	}

	// Update name + scopes.
	name := "Renamed App"
	scopes := []string{ScopeOpenID}
	updated, err := admin.UpdateClient(ctx, actor, client.ClientID, UpdateClientInput{
		ClientName: &name,
		Scopes:     &scopes,
	})
	if err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if updated.ClientName != name || len(updated.Scopes) != 1 {
		t.Fatalf("updated = %+v", updated)
	}

	// Invalid grant type rejected.
	badGrants := []string{"implicit"}
	_, err = admin.UpdateClient(ctx, actor, client.ClientID, UpdateClientInput{
		GrantTypes: &badGrants,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("UpdateClient bad grants err = %v, want ErrInvalidInput", err)
	}

	// Publish + list.
	published, err := admin.SetPublishStatus(
		ctx, actor, client.ClientID, oidcclient.PublishStatusPublished,
	)
	if err != nil || published.PublishStatus != oidcclient.PublishStatusPublished {
		t.Fatalf("SetPublishStatus = (%+v, %v)", published, err)
	}
	clients, err := admin.ListClients(ctx, actor, organizationID)
	if err != nil || len(clients) != 1 {
		t.Fatalf("ListClients = (%d, %v), want 1", len(clients), err)
	}

	// Redirect URI add/remove (add is idempotent).
	for range 2 {
		err = admin.AddRedirectURI(ctx, actor, client.ClientID, "https://app.test/cb2")
		if err != nil {
			t.Fatalf("AddRedirectURI: %v", err)
		}
	}
	got, err := admin.GetClient(ctx, actor, client.ClientID)
	if err != nil || len(got.Edges.CallbackUrls) != 2 {
		t.Fatalf("GetClient after add = (%d uris, %v), want 2", len(got.Edges.CallbackUrls), err)
	}
	err = admin.RemoveRedirectURI(ctx, actor, client.ClientID, "https://app.test/cb2")
	if err != nil {
		t.Fatalf("RemoveRedirectURI: %v", err)
	}

	// Allowlist round-trip (user must exist in authn).
	userID := uuid.New()
	err = db.UserRef.Create().SetID(userID).Exec(ctx)
	if err != nil {
		t.Fatalf("create user ref: %v", err)
	}
	for range 2 {
		err = admin.AddAccessGrant(ctx, actor, client.ClientID, userID)
		if err != nil {
			t.Fatalf("AddAccessGrant: %v", err)
		}
	}
	grants, err := admin.ListAccessGrants(ctx, actor, client.ClientID)
	if err != nil || len(grants) != 1 || grants[0].UserID != userID {
		t.Fatalf("ListAccessGrants = (%+v, %v), want one grant for %s", grants, err, userID)
	}
	err = admin.RemoveAccessGrant(ctx, actor, client.ClientID, userID)
	if err != nil {
		t.Fatalf("RemoveAccessGrant: %v", err)
	}

	// Unknown allowlist user is invalid input.
	err = admin.AddAccessGrant(ctx, actor, client.ClientID, uuid.New())
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("AddAccessGrant unknown user err = %v, want ErrInvalidInput", err)
	}
}

func TestAdminSecrets(t *testing.T) {
	t.Parallel()

	ctx, admin, _ := newAdminFixture(t, "oidcadminsecrets", true)
	actor := uuid.New()

	public, err := admin.CreateClient(ctx, actor, CreateClientInput{
		OrganizationID: uuid.New(),
		ClientName:     "Public App",
	})
	if err != nil {
		t.Fatalf("CreateClient public: %v", err)
	}
	_, err = admin.CreateSecret(ctx, actor, public.ClientID, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CreateSecret on public client err = %v, want ErrInvalidInput", err)
	}

	confidential, err := admin.CreateClient(ctx, actor, CreateClientInput{
		OrganizationID:          uuid.New(),
		ClientName:              "Server App",
		TokenEndpointAuthMethod: oidcclient.TokenEndpointAuthMethodClientSecretPost,
	})
	if err != nil {
		t.Fatalf("CreateClient confidential: %v", err)
	}

	created, err := admin.CreateSecret(ctx, actor, confidential.ClientID, nil)
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if created.ClientSecret == "" || created.Hint == "" {
		t.Fatalf("created secret = %+v, want plaintext + hint", created)
	}

	secrets, err := admin.ListSecrets(ctx, actor, confidential.ClientID)
	if err != nil || len(secrets) != 1 {
		t.Fatalf("ListSecrets = (%d, %v), want 1", len(secrets), err)
	}

	revoked, err := admin.RevokeSecret(ctx, actor, confidential.ClientID, created.SecretID)
	if err != nil || !revoked {
		t.Fatalf("RevokeSecret = (%v, %v), want true", revoked, err)
	}
	revoked, err = admin.RevokeSecret(ctx, actor, confidential.ClientID, created.SecretID)
	if err != nil || revoked {
		t.Fatalf("second RevokeSecret = (%v, %v), want false", revoked, err)
	}
}

func TestAdminPermissionDenied(t *testing.T) {
	t.Parallel()

	ctx, admin, _ := newAdminFixture(t, "oidcadminperm", false)
	actor := uuid.New()

	_, err := admin.CreateClient(ctx, actor, CreateClientInput{
		OrganizationID: uuid.New(),
		ClientName:     "Nope",
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("CreateClient err = %v, want ErrPermissionDenied", err)
	}

	_, err = admin.ListClients(ctx, actor, uuid.New())
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("ListClients err = %v, want ErrPermissionDenied", err)
	}
}
