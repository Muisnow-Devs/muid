// Package servicesgrpc implements the services gateway's curated BFF gRPC
// surface (ServicesGatewayService). Each handler reads the verified caller
// identity from the context (set by the gateway's auth interceptor) and
// delegates to backend services, attaching the identity as x-user-id metadata.
package servicesgrpc

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	gatewaypb "sanzi.io/muid/api/proto/gateway/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// Handler implements gatewaypb.ServicesGatewayServiceServer.
type Handler struct {
	gatewaypb.UnimplementedServicesGatewayServiceServer
	account authnpb.AccountServiceClient
	profile profilepb.ProfileServiceClient
}

// NewHandler builds a Handler backed by the account and profile services.
func NewHandler(account authnpb.AccountServiceClient, profile profilepb.ProfileServiceClient) *Handler {
	return &Handler{account: account, profile: profile}
}

// GetMe returns the authenticated caller's account and presentation profile.
func (h *Handler) GetMe(ctx context.Context, _ *gatewaypb.GetMeRequest) (*gatewaypb.GetMeResponse, error) {
	claims, ok := jwtauth.ClaimsFromContext(ctx)
	if !ok || claims.UserID == uuid.Nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	rawBearer, ok := jwtauth.RawBearerFromContext(ctx)
	if !ok || strings.TrimSpace(rawBearer) == "" {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	if h.account == nil {
		log.LogUnexpected(ctx, "gateway-services account lookup", "account client unavailable", log.UserID(claims.UserID))
		return nil, grpcutils.GRPCInternalError()
	}

	accountResp, err := h.account.GetMyAccount(
		accountOutgoingContext(ctx, claims.UserID, rawBearer),
		&authnpb.GetMyAccountRequest{},
	)
	if err != nil {
		return nil, accountLookupError(ctx, claims.UserID, err)
	}
	account, err := activeAccount(ctx, claims.UserID, accountResp)
	if err != nil {
		return nil, err
	}
	if h.profile == nil {
		log.LogUnexpected(ctx, "gateway-services profile lookup", "profile client unavailable", log.UserID(claims.UserID))
		return nil, grpcutils.GRPCInternalError()
	}

	req := &profilepb.GetProfileRequest{}
	req.SetId(claims.UserID.String())
	resp, err := h.profile.GetProfile(profileOutgoingContext(ctx, claims.UserID), req)
	if err != nil {
		return nil, profileLookupError(ctx, claims.UserID, err)
	}
	if resp == nil || resp.GetId() != claims.UserID.String() {
		log.LogUnexpected(ctx, "gateway-services profile response", "invalid profile response", log.UserID(claims.UserID))
		return nil, grpcutils.GRPCInternalError()
	}

	user := &gatewaypb.User{}
	user.SetId(account.GetUserId())
	user.SetUsername(resp.GetUsername())
	user.SetDisplayName(resp.GetDisplayName())
	user.SetEmail(account.GetPrimaryEmail())
	user.SetAvatarUrl(resp.GetAvatarUrl())

	out := &gatewaypb.GetMeResponse{}
	out.SetUser(user)
	return out, nil
}

func profileLookupError(ctx context.Context, userID uuid.UUID, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable:
		return err
	case codes.NotFound:
		return status.Error(codes.FailedPrecondition, "profile provisioning incomplete")
	default:
		log.LogUnexpected(ctx, "gateway-services profile lookup", "profile lookup failed", log.UserID(userID))
		return grpcutils.GRPCInternalError()
	}
}

func accountOutgoingContext(ctx context.Context, userID uuid.UUID, rawBearer string) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Delete(grpcutils.AuthorizationMetadataKey)
	md.Set(grpcutils.AuthorizationMetadataKey, "Bearer "+rawBearer)
	ctx = metadata.NewOutgoingContext(ctx, md)
	return httpmeta.WithOutgoing(ctx, httpmeta.Fields{UserID: userID.String()})
}

func profileOutgoingContext(ctx context.Context, userID uuid.UUID) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Delete(grpcutils.AuthorizationMetadataKey)
	ctx = metadata.NewOutgoingContext(ctx, md)
	return httpmeta.WithOutgoing(ctx, httpmeta.Fields{UserID: userID.String()})
}

func accountLookupError(ctx context.Context, userID uuid.UUID, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	switch status.Code(err) {
	case codes.NotFound:
		return status.Error(codes.Unauthenticated, "authentication required")
	case codes.Unauthenticated, codes.PermissionDenied, codes.Unavailable,
		codes.DeadlineExceeded, codes.Canceled:
		return err
	default:
		log.LogUnexpected(ctx, "gateway-services account lookup", err.Error(), log.UserID(userID))
		return grpcutils.GRPCInternalError()
	}
}

func activeAccount(
	ctx context.Context,
	userID uuid.UUID,
	resp *authnpb.GetMyAccountResponse,
) (*authnpb.Account, error) {
	account := resp.GetAccount()
	if account == nil || account.GetUserId() != userID.String() ||
		strings.TrimSpace(account.GetPrimaryEmail()) == "" || !account.GetPrimaryEmailVerified() {
		log.LogUnexpected(ctx, "gateway-services account response", "invalid account response", log.UserID(userID))
		return nil, grpcutils.GRPCInternalError()
	}
	switch account.GetAccountStatus() {
	case authnpb.AccountStatus_ACCOUNT_STATUS_ACTIVE:
		return account, nil
	case authnpb.AccountStatus_ACCOUNT_STATUS_DISABLED:
		return nil, status.Error(codes.PermissionDenied, "account disabled")
	case authnpb.AccountStatus_ACCOUNT_STATUS_PENDING_DELETION:
		return nil, status.Error(codes.FailedPrecondition, "account pending deletion")
	default:
		log.LogUnexpected(ctx, "gateway-services account response", "invalid account status", log.UserID(userID))
		return nil, grpcutils.GRPCInternalError()
	}
}
