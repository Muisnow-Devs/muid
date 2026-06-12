package authngrpc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/authn/v1"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/oidc"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// OIDCAdminHandler implements OIDCClientAdminService. A nil admin (OIDC not
// configured) makes every RPC return Unavailable.
type OIDCAdminHandler struct {
	pb.UnimplementedOIDCClientAdminServiceServer

	admin *oidc.Admin
}

func NewOIDCAdminHandler(admin *oidc.Admin) pb.OIDCClientAdminServiceServer {
	return &OIDCAdminHandler{admin: admin}
}

// actor resolves the acting user; the session principal interceptor enforces
// presence for every admin route.
func (h *OIDCAdminHandler) actor(ctx context.Context) (uuid.UUID, error) {
	if h.admin == nil {
		return uuid.Nil, errOIDCUnavailable
	}
	resolved, ok := ResolvedSessionFromContext(ctx)
	if !ok {
		return uuid.Nil, status.Error(codes.Unauthenticated, "session token required")
	}
	return resolved.UserID, nil
}

func adminDomainError(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, oidc.ErrClientNotFound):
		return status.Error(codes.NotFound, "client not found")
	case errors.Is(err, oidc.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, "missing authn/oidc_client.manage permission")
	case errors.Is(err, oidc.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		log.LogUnexpected(ctx, op, err.Error())
		return grpcutils.GRPCInternalError()
	}
}

// --- enum mappings (pb <-> ent) ---

func authMethodFromProto(in pb.OIDCTokenEndpointAuthMethod) oidcclient.TokenEndpointAuthMethod {
	switch in {
	case pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_NONE:
		return oidcclient.TokenEndpointAuthMethodNone
	case pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC:
		return oidcclient.TokenEndpointAuthMethodClientSecretBasic
	case pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_POST:
		return oidcclient.TokenEndpointAuthMethodClientSecretPost
	case pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_PRIVATE_KEY_JWT:
		return oidcclient.TokenEndpointAuthMethodPrivateKeyJwt
	default:
		return ""
	}
}

func authMethodProto(in oidcclient.TokenEndpointAuthMethod) pb.OIDCTokenEndpointAuthMethod {
	switch in {
	case oidcclient.TokenEndpointAuthMethodNone:
		return pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_NONE
	case oidcclient.TokenEndpointAuthMethodClientSecretBasic:
		return pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC
	case oidcclient.TokenEndpointAuthMethodClientSecretPost:
		return pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_POST
	case oidcclient.TokenEndpointAuthMethodPrivateKeyJwt:
		return pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_PRIVATE_KEY_JWT
	default:
		return pb.OIDCTokenEndpointAuthMethod_OIDC_TOKEN_ENDPOINT_AUTH_METHOD_UNSPECIFIED
	}
}

func applicationTypeFromProto(in pb.OIDCApplicationType) oidcclient.ApplicationType {
	switch in {
	case pb.OIDCApplicationType_OIDC_APPLICATION_TYPE_WEB:
		return oidcclient.ApplicationTypeWeb
	case pb.OIDCApplicationType_OIDC_APPLICATION_TYPE_NATIVE:
		return oidcclient.ApplicationTypeNative
	default:
		return ""
	}
}

func applicationTypeProto(in oidcclient.ApplicationType) pb.OIDCApplicationType {
	switch in {
	case oidcclient.ApplicationTypeWeb:
		return pb.OIDCApplicationType_OIDC_APPLICATION_TYPE_WEB
	case oidcclient.ApplicationTypeNative:
		return pb.OIDCApplicationType_OIDC_APPLICATION_TYPE_NATIVE
	default:
		return pb.OIDCApplicationType_OIDC_APPLICATION_TYPE_UNSPECIFIED
	}
}

func accessPolicyFromProto(in pb.OIDCAccessPolicy) oidcclient.AccessPolicy {
	switch in {
	case pb.OIDCAccessPolicy_OIDC_ACCESS_POLICY_PUBLIC:
		return oidcclient.AccessPolicyPublic
	case pb.OIDCAccessPolicy_OIDC_ACCESS_POLICY_ORGANIZATION:
		return oidcclient.AccessPolicyOrganization
	case pb.OIDCAccessPolicy_OIDC_ACCESS_POLICY_PRIVATE:
		return oidcclient.AccessPolicyPrivate
	default:
		return ""
	}
}

func accessPolicyProto(in oidcclient.AccessPolicy) pb.OIDCAccessPolicy {
	switch in {
	case oidcclient.AccessPolicyPublic:
		return pb.OIDCAccessPolicy_OIDC_ACCESS_POLICY_PUBLIC
	case oidcclient.AccessPolicyOrganization:
		return pb.OIDCAccessPolicy_OIDC_ACCESS_POLICY_ORGANIZATION
	case oidcclient.AccessPolicyPrivate:
		return pb.OIDCAccessPolicy_OIDC_ACCESS_POLICY_PRIVATE
	default:
		return pb.OIDCAccessPolicy_OIDC_ACCESS_POLICY_UNSPECIFIED
	}
}

func publishStatusFromProto(in pb.OIDCPublishStatus) oidcclient.PublishStatus {
	switch in {
	case pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_DRAFT:
		return oidcclient.PublishStatusDraft
	case pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_TESTING:
		return oidcclient.PublishStatusTesting
	case pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_PUBLISHED:
		return oidcclient.PublishStatusPublished
	case pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_DISABLED:
		return oidcclient.PublishStatusDisabled
	default:
		return ""
	}
}

func publishStatusProto(in oidcclient.PublishStatus) pb.OIDCPublishStatus {
	switch in {
	case oidcclient.PublishStatusDraft:
		return pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_DRAFT
	case oidcclient.PublishStatusTesting:
		return pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_TESTING
	case oidcclient.PublishStatusPublished:
		return pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_PUBLISHED
	case oidcclient.PublishStatusDisabled:
		return pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_DISABLED
	default:
		return pb.OIDCPublishStatus_OIDC_PUBLISH_STATUS_UNSPECIFIED
	}
}

func grantTypesFromProto(in []pb.OIDCGrantType) []string {
	out := make([]string, 0, len(in))
	for _, grantType := range in {
		switch grantType {
		case pb.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE:
			out = append(out, "authorization_code")
		case pb.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN:
			out = append(out, "refresh_token")
		case pb.OIDCGrantType_OIDC_GRANT_TYPE_DEVICE_CODE:
			out = append(out, "device_code")
		}
	}
	return out
}

func grantTypesProto(in []string) []pb.OIDCGrantType {
	out := make([]pb.OIDCGrantType, 0, len(in))
	for _, grantType := range in {
		switch grantType {
		case "authorization_code":
			out = append(out, pb.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE)
		case "refresh_token":
			out = append(out, pb.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
		case "device_code":
			out = append(out, pb.OIDCGrantType_OIDC_GRANT_TYPE_DEVICE_CODE)
		default:
			out = append(out, pb.OIDCGrantType_OIDC_GRANT_TYPE_UNSPECIFIED)
		}
	}
	return out
}

func clientInfoProto(client *authnent.OIDCClient) *pb.OIDCClientInfo {
	info := &pb.OIDCClientInfo{}
	info.SetClientId(client.ClientID)
	info.SetClientName(client.ClientName)
	info.SetOwnerOrganizationId(client.OwnerOrganizationID.String())
	info.SetScopes(client.Scopes)
	info.SetGrantTypes(grantTypesProto(client.GrantTypes))
	info.SetTokenEndpointAuthMethod(authMethodProto(client.TokenEndpointAuthMethod))
	info.SetApplicationType(applicationTypeProto(client.ApplicationType))
	info.SetAccessPolicy(accessPolicyProto(client.AccessPolicy))
	info.SetVerificationStatus(verificationStatusProto(client.VerificationStatus))
	info.SetPublishStatus(publishStatusProto(client.PublishStatus))
	info.SetCreatedAt(timestamppb.New(client.CreatedAt))
	info.SetUpdatedAt(timestamppb.New(client.UpdatedAt))

	uris := make([]string, 0, len(client.Edges.CallbackUrls))
	for _, callback := range client.Edges.CallbackUrls {
		uris = append(uris, callback.URI)
	}
	info.SetRedirectUris(uris)
	return info
}

// --- RPCs ---

func (h *OIDCAdminHandler) CreateOIDCClient(
	ctx context.Context,
	req *pb.CreateOIDCClientRequest,
) (*pb.CreateOIDCClientResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	organizationID, err := uuid.Parse(req.GetOrganizationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid organization id")
	}

	client, err := h.admin.CreateClient(ctx, actor, oidc.CreateClientInput{
		OrganizationID:          organizationID,
		ClientName:              req.GetClientName(),
		ApplicationType:         applicationTypeFromProto(req.GetApplicationType()),
		AccessPolicy:            accessPolicyFromProto(req.GetAccessPolicy()),
		TokenEndpointAuthMethod: authMethodFromProto(req.GetTokenEndpointAuthMethod()),
		Scopes:                  req.GetScopes(),
		RedirectURIs:            req.GetRedirectUris(),
		GrantTypes:              grantTypesFromProto(req.GetGrantTypes()),
	})
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin create client", err)
	}

	out := &pb.CreateOIDCClientResponse{}
	out.SetClient(clientInfoProto(client))
	return out, nil
}

func (h *OIDCAdminHandler) UpdateOIDCClient(
	ctx context.Context,
	req *pb.UpdateOIDCClientRequest,
) (*pb.UpdateOIDCClientResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}

	in := oidc.UpdateClientInput{
		AccessPolicy: accessPolicyFromProto(req.GetAccessPolicy()),
	}
	if req.HasClientName() {
		name := req.GetClientName()
		in.ClientName = &name
	}
	if req.HasScopes() {
		scopes := req.GetScopes().GetScopes()
		in.Scopes = &scopes
	}
	if req.HasGrantTypes() {
		grantTypes := grantTypesFromProto(req.GetGrantTypes().GetGrantTypes())
		in.GrantTypes = &grantTypes
	}

	client, err := h.admin.UpdateClient(ctx, actor, req.GetClientId(), in)
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin update client", err)
	}

	out := &pb.UpdateOIDCClientResponse{}
	out.SetClient(clientInfoProto(client))
	return out, nil
}

func (h *OIDCAdminHandler) SetOIDCClientPublishStatus(
	ctx context.Context,
	req *pb.SetOIDCClientPublishStatusRequest,
) (*pb.SetOIDCClientPublishStatusResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	publishStatus := publishStatusFromProto(req.GetPublishStatus())
	if publishStatus == "" {
		return nil, status.Error(codes.InvalidArgument, "publish status is required")
	}

	client, err := h.admin.SetPublishStatus(ctx, actor, req.GetClientId(), publishStatus)
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin publish status", err)
	}

	out := &pb.SetOIDCClientPublishStatusResponse{}
	out.SetClient(clientInfoProto(client))
	return out, nil
}

func (h *OIDCAdminHandler) GetOIDCClient(
	ctx context.Context,
	req *pb.GetOIDCClientRequest,
) (*pb.GetOIDCClientResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}

	client, err := h.admin.GetClient(ctx, actor, req.GetClientId())
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin get client", err)
	}

	out := &pb.GetOIDCClientResponse{}
	out.SetClient(clientInfoProto(client))
	return out, nil
}

func (h *OIDCAdminHandler) ListOIDCClients(
	ctx context.Context,
	req *pb.ListOIDCClientsRequest,
) (*pb.ListOIDCClientsResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	organizationID, err := uuid.Parse(req.GetOrganizationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid organization id")
	}

	clients, err := h.admin.ListClients(ctx, actor, organizationID)
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin list clients", err)
	}

	infos := make([]*pb.OIDCClientInfo, 0, len(clients))
	for _, client := range clients {
		infos = append(infos, clientInfoProto(client))
	}
	out := &pb.ListOIDCClientsResponse{}
	out.SetClients(infos)
	return out, nil
}

func (h *OIDCAdminHandler) AddOIDCClientRedirectURI(
	ctx context.Context,
	req *pb.AddOIDCClientRedirectURIRequest,
) (*pb.AddOIDCClientRedirectURIResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}

	err = h.admin.AddRedirectURI(ctx, actor, req.GetClientId(), req.GetUri())
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin add redirect uri", err)
	}

	out := &pb.AddOIDCClientRedirectURIResponse{}
	out.SetSuccess(true)
	return out, nil
}

func (h *OIDCAdminHandler) RemoveOIDCClientRedirectURI(
	ctx context.Context,
	req *pb.RemoveOIDCClientRedirectURIRequest,
) (*pb.RemoveOIDCClientRedirectURIResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}

	err = h.admin.RemoveRedirectURI(ctx, actor, req.GetClientId(), req.GetUri())
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin remove redirect uri", err)
	}

	out := &pb.RemoveOIDCClientRedirectURIResponse{}
	out.SetSuccess(true)
	return out, nil
}

func (h *OIDCAdminHandler) CreateOIDCClientSecret(
	ctx context.Context,
	req *pb.CreateOIDCClientSecretRequest,
) (*pb.CreateOIDCClientSecretResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if req.HasExpiresAt() {
		expiry := req.GetExpiresAt().AsTime()
		expiresAt = &expiry
	}

	created, err := h.admin.CreateSecret(ctx, actor, req.GetClientId(), expiresAt)
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin create secret", err)
	}

	out := &pb.CreateOIDCClientSecretResponse{}
	out.SetSecretId(created.SecretID.String())
	out.SetClientSecret(created.ClientSecret)
	out.SetHint(created.Hint)
	out.SetCreatedAt(timestamppb.New(created.CreatedAt))
	if created.ExpiresAt != nil {
		out.SetExpiresAt(timestamppb.New(*created.ExpiresAt))
	}
	return out, nil
}

func (h *OIDCAdminHandler) ListOIDCClientSecrets(
	ctx context.Context,
	req *pb.ListOIDCClientSecretsRequest,
) (*pb.ListOIDCClientSecretsResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}

	secrets, err := h.admin.ListSecrets(ctx, actor, req.GetClientId())
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin list secrets", err)
	}

	infos := make([]*pb.OIDCClientSecretInfo, 0, len(secrets))
	for _, secret := range secrets {
		info := &pb.OIDCClientSecretInfo{}
		info.SetSecretId(secret.ID.String())
		info.SetHint(secret.Hint)
		info.SetCreatedAt(timestamppb.New(secret.CreatedAt))
		if secret.ExpiresAt != nil {
			info.SetExpiresAt(timestamppb.New(*secret.ExpiresAt))
		}
		if secret.RevokedAt != nil {
			info.SetRevokedAt(timestamppb.New(*secret.RevokedAt))
		}
		if secret.LastUsedAt != nil {
			info.SetLastUsedAt(timestamppb.New(*secret.LastUsedAt))
		}
		infos = append(infos, info)
	}

	out := &pb.ListOIDCClientSecretsResponse{}
	out.SetSecrets(infos)
	return out, nil
}

func (h *OIDCAdminHandler) RevokeOIDCClientSecret(
	ctx context.Context,
	req *pb.RevokeOIDCClientSecretRequest,
) (*pb.RevokeOIDCClientSecretResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	secretID, err := uuid.Parse(req.GetSecretId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid secret id")
	}

	revoked, err := h.admin.RevokeSecret(ctx, actor, req.GetClientId(), secretID)
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin revoke secret", err)
	}

	out := &pb.RevokeOIDCClientSecretResponse{}
	out.SetSuccess(revoked)
	return out, nil
}

func (h *OIDCAdminHandler) AddOIDCClientAccessGrant(
	ctx context.Context,
	req *pb.AddOIDCClientAccessGrantRequest,
) (*pb.AddOIDCClientAccessGrantResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	err = h.admin.AddAccessGrant(ctx, actor, req.GetClientId(), userID)
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin add access grant", err)
	}

	out := &pb.AddOIDCClientAccessGrantResponse{}
	out.SetSuccess(true)
	return out, nil
}

func (h *OIDCAdminHandler) RemoveOIDCClientAccessGrant(
	ctx context.Context,
	req *pb.RemoveOIDCClientAccessGrantRequest,
) (*pb.RemoveOIDCClientAccessGrantResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	err = h.admin.RemoveAccessGrant(ctx, actor, req.GetClientId(), userID)
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin remove access grant", err)
	}

	out := &pb.RemoveOIDCClientAccessGrantResponse{}
	out.SetSuccess(true)
	return out, nil
}

func (h *OIDCAdminHandler) ListOIDCClientAccessGrants(
	ctx context.Context,
	req *pb.ListOIDCClientAccessGrantsRequest,
) (*pb.ListOIDCClientAccessGrantsResponse, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}

	grants, err := h.admin.ListAccessGrants(ctx, actor, req.GetClientId())
	if err != nil {
		return nil, adminDomainError(ctx, "oidc admin list access grants", err)
	}

	infos := make([]*pb.OIDCClientAccessGrantInfo, 0, len(grants))
	for _, grant := range grants {
		info := &pb.OIDCClientAccessGrantInfo{}
		info.SetUserId(grant.UserID.String())
		if grant.GrantedBy != uuid.Nil {
			info.SetGrantedBy(grant.GrantedBy.String())
		}
		info.SetCreatedAt(timestamppb.New(grant.CreatedAt))
		infos = append(infos, info)
	}

	out := &pb.ListOIDCClientAccessGrantsResponse{}
	out.SetGrants(infos)
	return out, nil
}
