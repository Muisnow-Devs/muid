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
func (g *GRPCHandler) ContinueAuthSession(
	context.Context,
	*pb.ContinueAuthSessionRequest,
) (*pb.ContinueAuthSessionResponse, error) {
	panic("unimplemented")
}

// GetAuthorizedSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) GetAuthorizedSession(
	context.Context,
	*pb.GetSessionRequest,
) (*pb.GetSessionResponse, error) {
	panic("unimplemented")
}

// GetPublicKeys implements [authn.AuthnServiceServer].
func (g *GRPCHandler) GetPublicKeys(
	context.Context,
	*pb.GetPublicKeysRequest,
) (*pb.GetPublicKeysResponse, error) {
	panic("unimplemented")
}

// OIDCGrantConsent implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCGrantConsent(
	context.Context,
	*pb.OIDCGrantConsentRequest,
) (*pb.OIDCGrantConsentResponse, error) {
	panic("unimplemented")
}

// OIDCIntrospectToken implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCIntrospectToken(
	context.Context,
	*pb.OIDCIntrospectTokenRequest,
) (*pb.OIDCIntrospectTokenResponse, error) {
	panic("unimplemented")
}

// OIDCListGrantedConsents implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCListGrantedConsents(
	context.Context,
	*pb.OIDCListGrantedConsentsRequest,
) (*pb.OIDCListGrantedConsentsResponse, error) {
	panic("unimplemented")
}

// OIDCRevokeConsent implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCRevokeConsent(
	context.Context,
	*pb.OIDCRevokeConsentRequest,
) (*pb.OIDCRevokeConsentResponse, error) {
	panic("unimplemented")
}

// OIDCRevokeRefreshToken implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCRevokeRefreshToken(
	context.Context,
	*pb.OIDCRevokeRefreshTokenRequest,
) (*pb.OIDCRevokeRefreshTokenResponse, error) {
	panic("unimplemented")
}

// OIDCRotateAndGetAccessToken implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCRotateAndGetAccessToken(
	context.Context,
	*pb.OIDCRotateAndGetAccessTokenRequest,
) (*pb.OIDCRotateAndGetAccessTokenResponse, error) {
	panic("unimplemented")
}

// RevokeFederatedIdentity implements [authn.AuthnServiceServer].
func (g *GRPCHandler) RevokeFederatedIdentity(
	context.Context,
	*pb.RevokeFederatedIdentityRequest,
) (*pb.RevokeFederatedIdentityResponse, error) {
	panic("unimplemented")
}

// RevokeSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) RevokeSession(
	context.Context,
	*pb.RevokeSessionRequest,
) (*pb.RevokeSessionResponse, error) {
	panic("unimplemented")
}

// StartAuthSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) StartAuthSession(
	context.Context,
	*pb.StartAuthSessionRequest,
) (*pb.StartAuthSessionResponse, error) {
	panic("unimplemented")
}
