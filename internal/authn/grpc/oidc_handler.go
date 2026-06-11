package authngrpc

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/oidc"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// deviceCodeGrantType is the RFC 8628 grant type URN advertised in discovery.
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// OIDCHandler implements the OIDCService gRPC server on top of the provider
// domain layer. A nil provider (OIDC not configured) makes every RPC return
// Unavailable.
type OIDCHandler struct {
	pb.UnimplementedOIDCServiceServer

	provider *oidc.Provider
}

func NewOIDCHandler(provider *oidc.Provider) pb.OIDCServiceServer {
	return &OIDCHandler{provider: provider}
}

var errOIDCUnavailable = status.Error(codes.Unavailable, "oidc provider is not configured")

func (h *OIDCHandler) ready() error {
	if h.provider == nil {
		return errOIDCUnavailable
	}
	return nil
}

// oidcDomainError maps non-OAuth domain failures to gRPC status errors.
func oidcDomainError(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, oidc.ErrClientNotFound):
		return status.Error(codes.InvalidArgument, "unknown client")
	case errors.Is(err, oidc.ErrRedirectURINotRegistered):
		return status.Error(codes.InvalidArgument, "redirect_uri is not registered")
	case errors.Is(err, oidc.ErrPendingNotFound):
		return status.Error(codes.NotFound, "authorization not found or expired")
	case errors.Is(err, oidc.ErrWrongUser):
		return status.Error(codes.PermissionDenied, "authorization belongs to another user")
	default:
		log.LogUnexpected(ctx, op, err.Error())
		return grpcutils.GRPCInternalError()
	}
}

func oauthErrorProto(oauthErr *oidc.OAuthError) *pb.OAuthError {
	out := &pb.OAuthError{}
	out.SetError(oauthErr.Code)
	out.SetErrorDescription(oauthErr.Description)
	return out
}

func verificationStatusProto(in oidcclient.VerificationStatus) pb.OIDCVerificationStatus {
	switch in {
	case oidcclient.VerificationStatusUnverified:
		return pb.OIDCVerificationStatus_OIDC_VERIFICATION_STATUS_UNVERIFIED
	case oidcclient.VerificationStatusPending:
		return pb.OIDCVerificationStatus_OIDC_VERIFICATION_STATUS_PENDING
	case oidcclient.VerificationStatusVerified:
		return pb.OIDCVerificationStatus_OIDC_VERIFICATION_STATUS_VERIFIED
	case oidcclient.VerificationStatusOfficial:
		return pb.OIDCVerificationStatus_OIDC_VERIFICATION_STATUS_OFFICIAL
	case oidcclient.VerificationStatusRejected:
		return pb.OIDCVerificationStatus_OIDC_VERIFICATION_STATUS_REJECTED
	default:
		return pb.OIDCVerificationStatus_OIDC_VERIFICATION_STATUS_UNSPECIFIED
	}
}

func scopeDescriptionsProto(details []oidc.ScopeDetail) []*pb.ScopeDescription {
	out := make([]*pb.ScopeDescription, 0, len(details))
	for _, detail := range details {
		desc := &pb.ScopeDescription{}
		desc.SetScope(detail.Scope)
		desc.SetName(detail.Name)
		desc.SetDescription(detail.Description)
		out = append(out, desc)
	}
	return out
}

func grantedCodeProto(granted *oidc.GrantedCode) *pb.AuthorizationGranted {
	out := &pb.AuthorizationGranted{}
	out.SetCode(granted.Code)
	out.SetState(granted.State)
	out.SetRedirectUri(granted.RedirectURI)
	return out
}

// sessionUserFromContext converts the enriched session principal (when
// present) into the domain SessionUser.
func sessionUserFromContext(ctx context.Context) *oidc.SessionUser {
	resolved, ok := ResolvedSessionFromContext(ctx)
	if !ok {
		return nil
	}
	return &oidc.SessionUser{
		UserID:    resolved.UserID,
		SessionID: resolved.SessionID,
		AuthTime:  resolved.IssuedAt,
	}
}

func (h *OIDCHandler) GetProviderMetadata(
	ctx context.Context,
	_ *pb.GetProviderMetadataRequest,
) (*pb.GetProviderMetadataResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	scopes, err := h.provider.SupportedScopes(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "oidc provider metadata", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	issuer := strings.TrimRight(h.provider.Issuer(), "/")
	out := &pb.GetProviderMetadataResponse{}
	out.SetIssuer(issuer)
	out.SetAuthorizationEndpoint(issuer + "/authorize")
	out.SetTokenEndpoint(issuer + "/token")
	out.SetDeviceAuthorizationEndpoint(issuer + "/device_authorization")
	out.SetUserinfoEndpoint(issuer + "/userinfo")
	out.SetJwksUri(issuer + "/.well-known/jwks.json")
	out.SetScopesSupported(scopes)
	out.SetResponseTypesSupported([]string{"code"})
	out.SetGrantTypesSupported([]string{
		"authorization_code",
		"refresh_token",
		deviceCodeGrantType,
	})
	out.SetCodeChallengeMethodsSupported([]string{"S256"})
	out.SetTokenEndpointAuthMethodsSupported([]string{
		"none",
		"client_secret_basic",
		"client_secret_post",
	})
	out.SetIdTokenSigningAlgValuesSupported([]string{"RS256"})
	out.SetSubjectTypesSupported([]string{"public"})
	return out, nil
}

func (h *OIDCHandler) Authorize(
	ctx context.Context,
	req *pb.AuthorizeRequest,
) (*pb.AuthorizeResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	result, err := h.provider.Authorize(ctx, oidc.AuthorizeInput{
		ClientID:            req.GetClientId(),
		RedirectURI:         req.GetRedirectUri(),
		ResponseType:        req.GetResponseType(),
		Scopes:              req.GetScopes(),
		State:               req.GetState(),
		Nonce:               req.GetNonce(),
		CodeChallenge:       req.GetCodeChallenge(),
		CodeChallengeMethod: req.GetCodeChallengeMethod(),
		Prompt:              req.GetPrompt(),
	}, sessionUserFromContext(ctx))

	out := &pb.AuthorizeResponse{}
	if oauthErr, ok := oidc.AsOAuthError(err); ok {
		out.SetError(oauthErrorProto(oauthErr))
		return out, nil
	}
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc authorize", err)
	}

	switch {
	case result.Granted != nil:
		out.SetGranted(grantedCodeProto(result.Granted))
	case result.Consent != nil:
		consent := &pb.ConsentRequired{}
		consent.SetAuthorizationId(result.Consent.AuthorizationID.String())
		consent.SetClientName(result.Consent.ClientName)
		consent.SetVerificationStatus(verificationStatusProto(result.Consent.VerificationStatus))
		consent.SetScopes(scopeDescriptionsProto(result.Consent.Scopes))
		out.SetConsentRequired(consent)
	default:
		out.SetLoginRequired(&pb.LoginRequired{})
	}
	return out, nil
}

func (h *OIDCHandler) DecideConsent(
	ctx context.Context,
	req *pb.DecideConsentRequest,
) (*pb.DecideConsentResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	user := sessionUserFromContext(ctx)
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "session token required")
	}
	authorizationID, err := uuid.Parse(req.GetAuthorizationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid authorization id")
	}
	approve, err := consentDecision(req.GetDecision())
	if err != nil {
		return nil, err
	}

	outcome, err := h.provider.DecideConsent(ctx, *user, authorizationID, approve)
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc decide consent", err)
	}

	out := &pb.DecideConsentResponse{}
	if outcome.Denied != nil {
		denied := &pb.ConsentDenied{}
		denied.SetError(oauthErrorProto(outcome.Denied.Err))
		denied.SetRedirectUri(outcome.Denied.RedirectURI)
		denied.SetState(outcome.Denied.State)
		out.SetDenied(denied)
		return out, nil
	}
	out.SetGranted(grantedCodeProto(outcome.Granted))
	return out, nil
}

func consentDecision(decision pb.OIDCConsentDecision) (bool, error) {
	switch decision {
	case pb.OIDCConsentDecision_OIDC_CONSENT_DECISION_APPROVE:
		return true, nil
	case pb.OIDCConsentDecision_OIDC_CONSENT_DECISION_DENY:
		return false, nil
	default:
		return false, status.Error(codes.InvalidArgument, "decision is required")
	}
}

func (h *OIDCHandler) ExchangeToken(
	ctx context.Context,
	req *pb.ExchangeTokenRequest,
) (*pb.ExchangeTokenResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	in := oidc.ExchangeInput{
		ClientID:     req.GetClientId(),
		ClientSecret: req.GetClientSecret(),
	}
	switch {
	case req.GetAuthorizationCode() != nil:
		grant := req.GetAuthorizationCode()
		in.Code = &oidc.CodeGrantInput{
			Code:         grant.GetCode(),
			RedirectURI:  grant.GetRedirectUri(),
			CodeVerifier: grant.GetCodeVerifier(),
		}
	case req.GetRefreshToken() != nil:
		grant := req.GetRefreshToken()
		in.Refresh = &oidc.RefreshGrantInput{
			RefreshToken: grant.GetRefreshToken(),
			Scopes:       grant.GetScopes(),
		}
	case req.GetDeviceCode() != nil:
		in.Device = &oidc.DeviceGrantInput{DeviceCode: req.GetDeviceCode().GetDeviceCode()}
	}

	result, err := h.provider.ExchangeToken(ctx, in)
	out := &pb.ExchangeTokenResponse{}
	if oauthErr, ok := oidc.AsOAuthError(err); ok {
		out.SetError(oauthErrorProto(oauthErr))
		return out, nil
	}
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc exchange token", err)
	}

	out.SetSuccess(tokenSuccessProto(result))
	return out, nil
}

func tokenSuccessProto(result oidc.TokenOutput) *pb.TokenSuccess {
	success := &pb.TokenSuccess{}
	success.SetAccessToken(result.AccessToken)
	success.SetTokenType("Bearer")
	success.SetExpiresIn(result.ExpiresIn)
	success.SetRefreshToken(result.RefreshToken)
	success.SetIdToken(result.IDToken)
	success.SetScopes(result.Scopes)
	return success
}

func (h *OIDCHandler) StartDeviceAuthorization(
	ctx context.Context,
	req *pb.StartDeviceAuthorizationRequest,
) (*pb.StartDeviceAuthorizationResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	result, err := h.provider.StartDeviceAuthorization(
		ctx,
		req.GetClientId(),
		req.GetClientSecret(),
		req.GetScopes(),
	)
	out := &pb.StartDeviceAuthorizationResponse{}
	if oauthErr, ok := oidc.AsOAuthError(err); ok {
		out.SetError(oauthErrorProto(oauthErr))
		return out, nil
	}
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc device authorization", err)
	}

	success := &pb.DeviceAuthorizationSuccess{}
	success.SetDeviceCode(result.DeviceCode)
	success.SetUserCode(result.UserCode)
	success.SetVerificationUri(result.VerificationURI)
	success.SetVerificationUriComplete(result.VerificationURIComplete)
	success.SetExpiresIn(result.ExpiresIn)
	success.SetInterval(result.Interval)
	out.SetSuccess(success)
	return out, nil
}

func (h *OIDCHandler) GetDeviceAuthorizationInfo(
	ctx context.Context,
	req *pb.GetDeviceAuthorizationInfoRequest,
) (*pb.GetDeviceAuthorizationInfoResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	info, err := h.provider.DeviceAuthorizationInfo(ctx, req.GetUserCode())
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc device info", err)
	}

	out := &pb.GetDeviceAuthorizationInfoResponse{}
	out.SetClientId(info.ClientID)
	out.SetClientName(info.ClientName)
	out.SetVerificationStatus(verificationStatusProto(info.VerificationStatus))
	out.SetScopes(scopeDescriptionsProto(info.Scopes))
	return out, nil
}

func (h *OIDCHandler) DecideDeviceAuthorization(
	ctx context.Context,
	req *pb.DecideDeviceAuthorizationRequest,
) (*pb.DecideDeviceAuthorizationResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	user := sessionUserFromContext(ctx)
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "session token required")
	}
	approve, err := consentDecision(req.GetDecision())
	if err != nil {
		return nil, err
	}

	err = h.provider.DecideDeviceAuthorization(ctx, *user, req.GetUserCode(), approve)
	out := &pb.DecideDeviceAuthorizationResponse{}
	if oauthErr, ok := oidc.AsOAuthError(err); ok {
		out.SetError(oauthErrorProto(oauthErr))
		return out, nil
	}
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc device decision", err)
	}

	out.SetRecorded(&pb.DeviceDecisionRecorded{})
	return out, nil
}

func (h *OIDCHandler) IntrospectToken(
	ctx context.Context,
	req *pb.IntrospectTokenRequest,
) (*pb.IntrospectTokenResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	result, err := h.provider.IntrospectToken(
		ctx,
		req.GetClientId(),
		req.GetClientSecret(),
		req.GetToken(),
		req.GetTokenTypeHint(),
	)
	out := &pb.IntrospectTokenResponse{}
	if oauthErr, ok := oidc.AsOAuthError(err); ok {
		out.SetError(oauthErrorProto(oauthErr))
		return out, nil
	}
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc introspect token", err)
	}

	introspection := &pb.IntrospectionResult{}
	introspection.SetActive(result.Active)
	if result.Active {
		introspection.SetScopes(result.Scopes)
		introspection.SetClientId(result.ClientID)
		introspection.SetTokenType(result.TokenType)
		introspection.SetSub(result.Subject.String())
		introspection.SetAud(result.Audience)
		introspection.SetIss(result.Issuer)
		introspection.SetIssuedAt(timestamppb.New(result.IssuedAt))
		introspection.SetExpiresAt(timestamppb.New(result.ExpiresAt))
	}
	out.SetIntrospection(introspection)
	return out, nil
}

func (h *OIDCHandler) RevokeToken(
	ctx context.Context,
	req *pb.RevokeTokenRequest,
) (*pb.RevokeTokenResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	err := h.provider.RevokeToken(ctx, req.GetClientId(), req.GetClientSecret(), req.GetToken())
	out := &pb.RevokeTokenResponse{}
	if oauthErr, ok := oidc.AsOAuthError(err); ok {
		out.SetError(oauthErrorProto(oauthErr))
		return out, nil
	}
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc revoke token", err)
	}

	out.SetSuccess(&pb.RevocationSuccess{})
	return out, nil
}

func (h *OIDCHandler) GetUserInfo(
	ctx context.Context,
	req *pb.GetUserInfoRequest,
) (*pb.GetUserInfoResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}

	result, err := h.provider.UserInfo(ctx, req.GetAccessToken())
	out := &pb.GetUserInfoResponse{}
	if oauthErr, ok := oidc.AsOAuthError(err); ok {
		out.SetError(oauthErrorProto(oauthErr))
		return out, nil
	}
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc userinfo", err)
	}

	info := &pb.UserInfo{}
	info.SetSub(result.Subject.String())
	if result.Name != nil {
		info.SetName(*result.Name)
	}
	if result.Picture != nil {
		info.SetPicture(*result.Picture)
	}
	if result.PreferredUsername != nil {
		info.SetPreferredUsername(*result.PreferredUsername)
	}
	if result.Locale != nil {
		info.SetLocale(*result.Locale)
	}
	if result.Zoneinfo != nil {
		info.SetZoneinfo(*result.Zoneinfo)
	}
	if result.Email != nil {
		info.SetEmail(*result.Email)
	}
	if result.EmailVerified != nil {
		info.SetEmailVerified(*result.EmailVerified)
	}
	out.SetUserInfo(info)
	return out, nil
}

func (h *OIDCHandler) ListGrantedConsents(
	ctx context.Context,
	_ *pb.ListGrantedConsentsRequest,
) (*pb.ListGrantedConsentsResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	user := sessionUserFromContext(ctx)
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "session token required")
	}

	consents, err := h.provider.ListGrantedConsents(ctx, user.UserID)
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc list consents", err)
	}

	clients := make([]*pb.AuthorizedClient, 0, len(consents))
	for _, consent := range consents {
		client := &pb.AuthorizedClient{}
		client.SetClientId(consent.ClientID)
		client.SetClientName(consent.ClientName)
		client.SetScopes(consent.Scopes)
		client.SetAuthorizedAt(timestamppb.New(consent.AuthorizedAt))
		if !consent.LastUsedAt.IsZero() {
			client.SetLastUsedAt(timestamppb.New(consent.LastUsedAt))
		}
		clients = append(clients, client)
	}

	out := &pb.ListGrantedConsentsResponse{}
	out.SetClients(clients)
	return out, nil
}

func (h *OIDCHandler) RevokeConsent(
	ctx context.Context,
	req *pb.RevokeConsentRequest,
) (*pb.RevokeConsentResponse, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	user := sessionUserFromContext(ctx)
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "session token required")
	}

	revoked, err := h.provider.RevokeConsent(ctx, user.UserID, req.GetClientId())
	if err != nil {
		return nil, oidcDomainError(ctx, "oidc revoke consent", err)
	}

	out := &pb.RevokeConsentResponse{}
	out.SetSuccess(revoked)
	return out, nil
}
