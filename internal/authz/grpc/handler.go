package authzgrpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/internal/signature"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

type GRPCHandler struct {
	pb.UnimplementedAuthzServiceServer

	signing signature.SignatureManager
}

type HandlerConfig struct {
	SignatureManager signature.SignatureManager
}

func NewGRPCHandler(config HandlerConfig) pb.AuthzServiceServer {
	return &GRPCHandler{
		signing: config.SignatureManager,
	}
}

func (g *GRPCHandler) GetPublicKeys(
	ctx context.Context,
	_ *pb.GetPublicKeysRequest,
) (*pb.GetPublicKeysResponse, error) {
	if g.signing == nil {
		return nil, status.Error(codes.Unavailable, "signature manager unavailable")
	}

	keys, err := g.signing.PublicKeys(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "authz public keys", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetPublicKeysResponse{}
	out.SetPublicKeys(keys)
	return out, nil
}

func (g *GRPCHandler) OIDCGrantConsent(
	context.Context,
	*pb.OIDCGrantConsentRequest,
) (*pb.OIDCGrantConsentResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCGrantConsent not implemented")
}

func (g *GRPCHandler) OIDCIntrospectToken(
	context.Context,
	*pb.OIDCIntrospectTokenRequest,
) (*pb.OIDCIntrospectTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCIntrospectToken not implemented")
}

func (g *GRPCHandler) OIDCListGrantedConsents(
	context.Context,
	*pb.OIDCListGrantedConsentsRequest,
) (*pb.OIDCListGrantedConsentsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCListGrantedConsents not implemented")
}

func (g *GRPCHandler) OIDCRevokeConsent(
	context.Context,
	*pb.OIDCRevokeConsentRequest,
) (*pb.OIDCRevokeConsentResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCRevokeConsent not implemented")
}

func (g *GRPCHandler) OIDCRevokeRefreshToken(
	context.Context,
	*pb.OIDCRevokeRefreshTokenRequest,
) (*pb.OIDCRevokeRefreshTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCRevokeRefreshToken not implemented")
}

func (g *GRPCHandler) OIDCRotateAndGetAccessToken(
	context.Context,
	*pb.OIDCRotateAndGetAccessTokenRequest,
) (*pb.OIDCRotateAndGetAccessTokenResponse, error) {
	return nil, status.Error(
		codes.Unimplemented,
		"method OIDCRotateAndGetAccessToken not implemented",
	)
}
