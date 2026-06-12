package oidc

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidccallbackuri"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/ent/oidcclientaccessgrant"
	"sanzi.io/muid/internal/authn/ent/oidcclientsecret"
	"sanzi.io/muid/internal/authn/oidc/policy"
)

// PermissionManageClients is the org permission required for client
// administration (seed it on the org admin/owner system roles).
const PermissionManageClients = "authn/oidc_client.manage"

var (
	// ErrPermissionDenied: the actor lacks PermissionManageClients in the
	// owning organization (gRPC PermissionDenied).
	ErrPermissionDenied = errors.New("oidc admin: permission denied")
	// ErrInvalidInput: the request is structurally valid but semantically
	// wrong (gRPC InvalidArgument with this message).
	ErrInvalidInput = errors.New("oidc admin: invalid input")
)

// PermissionChecker answers organization permission questions (backed by the
// authz service).
type PermissionChecker interface {
	HasPermission(
		ctx context.Context,
		organizationID, userID uuid.UUID,
		permission string,
	) (bool, error)
}

// Admin implements organization-scoped OIDC client management. Every method
// takes the acting user and enforces PermissionManageClients in the client's
// owning organization.
type Admin struct {
	db    *ent.Client
	perms PermissionChecker
}

func NewAdmin(db *ent.Client, perms PermissionChecker) *Admin {
	return &Admin{db: db, perms: perms}
}

func (a *Admin) authorize(ctx context.Context, actor, organizationID uuid.UUID) error {
	allowed, err := a.perms.HasPermission(ctx, organizationID, actor, PermissionManageClients)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// managedClient loads a non-deleted client by public client_id and checks
// the actor's permission on its owning organization.
func (a *Admin) managedClient(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
) (*ent.OIDCClient, error) {
	client, err := a.db.OIDCClient.Query().
		Where(oidcclient.ClientID(clientID), oidcclient.DeletedAtIsNil()).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}

	err = a.authorize(ctx, actor, client.OwnerOrganizationID)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// withRedirectURIs reloads the client with its callback URIs for responses.
func (a *Admin) withRedirectURIs(
	ctx context.Context,
	client *ent.OIDCClient,
) (*ent.OIDCClient, error) {
	return a.db.OIDCClient.Query().
		Where(oidcclient.ID(client.ID)).
		WithCallbackUrls().
		Only(ctx)
}

var validGrantTypes = []string{
	policy.GrantTypeAuthorizationCode,
	policy.GrantTypeRefreshToken,
	policy.GrantTypeDeviceCode,
}

func validateGrantTypes(grantTypes []string) error {
	for _, grantType := range grantTypes {
		if !slices.Contains(validGrantTypes, grantType) {
			return errors.Join(ErrInvalidInput, errors.New("unknown grant type "+grantType))
		}
	}
	return nil
}

// CreateClientInput uses ent enum types; zero values fall back to schema
// defaults.
type CreateClientInput struct {
	OrganizationID          uuid.UUID
	ClientName              string
	ApplicationType         oidcclient.ApplicationType
	AccessPolicy            oidcclient.AccessPolicy
	TokenEndpointAuthMethod oidcclient.TokenEndpointAuthMethod
	Scopes                  []string
	RedirectURIs            []string
	GrantTypes              []string
}

func (a *Admin) CreateClient(
	ctx context.Context,
	actor uuid.UUID,
	in CreateClientInput,
) (*ent.OIDCClient, error) {
	err := a.authorize(ctx, actor, in.OrganizationID)
	if err != nil {
		return nil, err
	}
	err = validateGrantTypes(in.GrantTypes)
	if err != nil {
		return nil, err
	}

	// Native apps cannot keep a secret; force the public client profile.
	if in.ApplicationType == oidcclient.ApplicationTypeNative ||
		in.TokenEndpointAuthMethod == "" {
		in.TokenEndpointAuthMethod = oidcclient.TokenEndpointAuthMethodNone
	}

	clientID, err := randomToken(24)
	if err != nil {
		return nil, err
	}

	builder := a.db.OIDCClient.Create().
		SetClientID(clientID).
		SetClientName(in.ClientName).
		SetOwnerOrganizationID(in.OrganizationID).
		SetScopes(in.Scopes).
		SetTokenEndpointAuthMethod(in.TokenEndpointAuthMethod)
	if in.ApplicationType != "" {
		builder.SetApplicationType(in.ApplicationType)
	}
	if in.AccessPolicy != "" {
		builder.SetAccessPolicy(in.AccessPolicy)
	}
	if len(in.GrantTypes) > 0 {
		builder.SetGrantTypes(in.GrantTypes)
	}

	client, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}

	for _, uri := range in.RedirectURIs {
		err = a.db.OIDCCallbackURI.Create().
			SetClientRefID(client.ID).
			SetURI(uri).
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return a.withRedirectURIs(ctx, client)
}

// UpdateClientInput: nil pointers leave the field unchanged.
type UpdateClientInput struct {
	ClientName   *string
	AccessPolicy oidcclient.AccessPolicy
	Scopes       *[]string
	GrantTypes   *[]string
}

func (a *Admin) UpdateClient(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
	in UpdateClientInput,
) (*ent.OIDCClient, error) {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return nil, err
	}

	builder := a.db.OIDCClient.UpdateOneID(client.ID)
	if in.ClientName != nil {
		builder.SetClientName(*in.ClientName)
	}
	if in.AccessPolicy != "" {
		builder.SetAccessPolicy(in.AccessPolicy)
	}
	if in.Scopes != nil {
		builder.SetScopes(*in.Scopes)
	}
	if in.GrantTypes != nil {
		err = validateGrantTypes(*in.GrantTypes)
		if err != nil {
			return nil, err
		}
		builder.SetGrantTypes(*in.GrantTypes)
	}

	client, err = builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return a.withRedirectURIs(ctx, client)
}

func (a *Admin) SetPublishStatus(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
	status oidcclient.PublishStatus,
) (*ent.OIDCClient, error) {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return nil, err
	}

	client, err = a.db.OIDCClient.UpdateOneID(client.ID).
		SetPublishStatus(status).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return a.withRedirectURIs(ctx, client)
}

func (a *Admin) GetClient(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
) (*ent.OIDCClient, error) {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return nil, err
	}
	return a.withRedirectURIs(ctx, client)
}

func (a *Admin) ListClients(
	ctx context.Context,
	actor uuid.UUID,
	organizationID uuid.UUID,
) ([]*ent.OIDCClient, error) {
	err := a.authorize(ctx, actor, organizationID)
	if err != nil {
		return nil, err
	}

	return a.db.OIDCClient.Query().
		Where(
			oidcclient.OwnerOrganizationID(organizationID),
			oidcclient.DeletedAtIsNil(),
		).
		WithCallbackUrls().
		Order(oidcclient.ByCreatedAt()).
		All(ctx)
}

func (a *Admin) AddRedirectURI(
	ctx context.Context,
	actor uuid.UUID,
	clientID, uri string,
) error {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return err
	}

	err = a.db.OIDCCallbackURI.Create().
		SetClientRefID(client.ID).
		SetURI(uri).
		Exec(ctx)
	if ent.IsConstraintError(err) {
		// Already registered; adding is idempotent.
		return nil
	}
	return err
}

func (a *Admin) RemoveRedirectURI(
	ctx context.Context,
	actor uuid.UUID,
	clientID, uri string,
) error {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return err
	}

	_, err = a.db.OIDCCallbackURI.Delete().
		Where(
			oidccallbackuri.ClientRefID(client.ID),
			oidccallbackuri.URI(uri),
		).
		Exec(ctx)
	return err
}

// CreatedSecret carries the one-time plaintext secret.
type CreatedSecret struct {
	SecretID     uuid.UUID
	ClientSecret string
	Hint         string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
}

func (a *Admin) CreateSecret(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
	expiresAt *time.Time,
) (CreatedSecret, error) {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return CreatedSecret{}, err
	}
	if client.TokenEndpointAuthMethod == oidcclient.TokenEndpointAuthMethodNone {
		return CreatedSecret{}, errors.Join(
			ErrInvalidInput,
			errors.New("public clients (auth method none) cannot have secrets"),
		)
	}

	plaintext, err := randomToken(32)
	if err != nil {
		return CreatedSecret{}, err
	}
	hint := plaintext[:4] + "…" + plaintext[len(plaintext)-4:]

	builder := a.db.OIDCClientSecret.Create().
		SetClientRefID(client.ID).
		SetSecretHash(HashClientSecret(plaintext)).
		SetHint(hint)
	if expiresAt != nil {
		builder.SetExpiresAt(*expiresAt)
	}
	row, err := builder.Save(ctx)
	if err != nil {
		return CreatedSecret{}, err
	}

	return CreatedSecret{
		SecretID:     row.ID,
		ClientSecret: plaintext,
		Hint:         hint,
		CreatedAt:    row.CreatedAt,
		ExpiresAt:    row.ExpiresAt,
	}, nil
}

func (a *Admin) ListSecrets(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
) ([]*ent.OIDCClientSecret, error) {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return nil, err
	}

	return a.db.OIDCClientSecret.Query().
		Where(oidcclientsecret.ClientRefID(client.ID)).
		Order(oidcclientsecret.ByCreatedAt()).
		All(ctx)
}

func (a *Admin) RevokeSecret(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
	secretID uuid.UUID,
) (bool, error) {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return false, err
	}

	revoked, err := a.db.OIDCClientSecret.Update().
		Where(
			oidcclientsecret.ID(secretID),
			oidcclientsecret.ClientRefID(client.ID),
			oidcclientsecret.RevokedAtIsNil(),
		).
		SetRevokedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return revoked > 0, nil
}

func (a *Admin) AddAccessGrant(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
	userID uuid.UUID,
) error {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return err
	}

	err = a.db.OIDCClientAccessGrant.Create().
		SetClientRefID(client.ID).
		SetUserID(userID).
		SetGrantedBy(actor).
		Exec(ctx)
	if ent.IsConstraintError(err) {
		// Already allowlisted (or the user is unknown to authn). Adding an
		// existing grant is idempotent; unknown users surface as a
		// constraint violation on the user edge.
		exists, existsErr := a.db.OIDCClientAccessGrant.Query().
			Where(
				oidcclientaccessgrant.ClientRefID(client.ID),
				oidcclientaccessgrant.UserID(userID),
			).
			Exist(ctx)
		if existsErr != nil {
			return existsErr
		}
		if exists {
			return nil
		}
		return errors.Join(ErrInvalidInput, errors.New("unknown user"))
	}
	return err
}

func (a *Admin) RemoveAccessGrant(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
	userID uuid.UUID,
) error {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return err
	}

	_, err = a.db.OIDCClientAccessGrant.Delete().
		Where(
			oidcclientaccessgrant.ClientRefID(client.ID),
			oidcclientaccessgrant.UserID(userID),
		).
		Exec(ctx)
	return err
}

func (a *Admin) ListAccessGrants(
	ctx context.Context,
	actor uuid.UUID,
	clientID string,
) ([]*ent.OIDCClientAccessGrant, error) {
	client, err := a.managedClient(ctx, actor, clientID)
	if err != nil {
		return nil, err
	}

	return a.db.OIDCClientAccessGrant.Query().
		Where(oidcclientaccessgrant.ClientRefID(client.ID)).
		Order(oidcclientaccessgrant.ByCreatedAt()).
		All(ctx)
}
