package app

import (
	"context"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/otp"
)

type GRPCHandler struct {
	pb.UnimplementedAuthnServiceServer

	optStore otp.OTPStore
}

func CreateGRPCHandler(infra *InfraDependencies) pb.AuthnServiceServer {
	return &GRPCHandler{
		optStore: infra.OTPStore,
	}
}

// ContinueAuthSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) ContinueAuthSession(context.Context, *pb.ContinueAuthSessionRequest) (*pb.ContinueAuthSessionResponse, error) {
	panic("unimplemented")
}

// GetAuthorizedSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) GetAuthorizedSession(context.Context, *pb.GetSessionRequest) (*pb.GetSessionResponse, error) {
	panic("unimplemented")
}

// GetPublicKeys implements [authn.AuthnServiceServer].
func (g *GRPCHandler) GetPublicKeys(context.Context, *pb.GetPublicKeysRequest) (*pb.GetPublicKeysResponse, error) {
	panic("unimplemented")
}

// ListAuthorizedClients implements [authn.AuthnServiceServer].
func (g *GRPCHandler) ListAuthorizedClients(context.Context, *pb.ListAuthorizedClientsRequest) (*pb.ListAuthorizedClientsResponse, error) {
	panic("unimplemented")
}

// RefreshToken implements [authn.AuthnServiceServer].
func (g *GRPCHandler) RefreshToken(context.Context, *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	panic("unimplemented")
}

// RevokeAuthorization implements [authn.AuthnServiceServer].
func (g *GRPCHandler) RevokeAuthorization(context.Context, *pb.RevokeAuthorizationRequest) (*pb.RevokeAuthorizationResponse, error) {
	panic("unimplemented")
}

// RevokeSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) RevokeSession(context.Context, *pb.RevokeSessionRequest) (*pb.RevokeSessionResponse, error) {
	panic("unimplemented")
}

// StartAuthSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) StartAuthSession(context.Context, *pb.StartAuthSessionRequest) (*pb.StartAuthSessionResponse, error) {
	panic("unimplemented")
}
