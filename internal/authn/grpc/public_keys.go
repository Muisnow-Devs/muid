package authngrpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// GetPublicKeys serves the JWT signing public keys (JWKS source) for session
// access tokens and OIDC provider tokens. No authentication required.
func (g *GRPCHandler) GetPublicKeys(
	ctx context.Context,
	_ *pb.GetPublicKeysRequest,
) (*pb.GetPublicKeysResponse, error) {
	if g.signing == nil {
		return nil, status.Error(codes.Unavailable, "signature manager unavailable")
	}

	keys, err := g.signing.PublicKeys(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "authn public keys", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetPublicKeysResponse{}
	out.SetPublicKeys(keys)
	return out, nil
}
