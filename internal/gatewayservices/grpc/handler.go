// Package servicesgrpc implements the services gateway's curated BFF gRPC
// surface (ServicesGatewayService). Each handler reads the verified caller
// identity from the context (set by the gateway's auth interceptor) and
// delegates to backend services, attaching the identity as x-user-id metadata.
package servicesgrpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	profile profilepb.ProfileServiceClient
}

// NewHandler builds a Handler backed by the profile service.
func NewHandler(profile profilepb.ProfileServiceClient) *Handler {
	return &Handler{profile: profile}
}

// GetMe returns the authenticated caller's profile.
func (h *Handler) GetMe(ctx context.Context, _ *gatewaypb.GetMeRequest) (*gatewaypb.GetMeResponse, error) {
	claims, ok := jwtauth.ClaimsFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	// Forward the verified identity to the profile service as x-user-id.
	outCtx := httpmeta.WithOutgoing(ctx, httpmeta.Fields{UserID: claims.UserID.String()})

	req := &profilepb.GetProfileRequest{}
	req.SetId(claims.UserID.String())
	resp, err := h.profile.GetProfile(outCtx, req)
	if err != nil {
		log.LogUnexpected(ctx, "gateway-services profile lookup", err.Error(), log.UserID(claims.UserID))
		return nil, grpcutils.GRPCInternalError()
	}

	user := &gatewaypb.User{}
	user.SetId(resp.GetId())
	user.SetUsername(resp.GetUsername())
	user.SetDisplayName(resp.GetDisplayName())
	user.SetEmail(resp.GetEmail())
	user.SetAvatarUrl(resp.GetAvatarUrl())

	out := &gatewaypb.GetMeResponse{}
	out.SetUser(user)
	return out, nil
}
