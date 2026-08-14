package authngrpc

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/internal/oidctoken"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

const (
	accountDelegationAudience  = "authn-account"
	accountServiceMethodPrefix = "/muid.authn.v1.AccountService/"
)

type accountDelegationVerifier interface {
	VerifySessionAccessToken(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error)
}

// AccountDelegationInterceptor authenticates the gateway-services delegation
// token for GetMyAccount and removes it before the session-token parser runs.
func AccountDelegationInterceptor(verifier accountDelegationVerifier) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if !strings.HasPrefix(info.FullMethod, accountServiceMethodPrefix) {
			return handler(ctx, req)
		}

		raw, ok := accountBearer(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid account delegation")
		}
		userID, ok := grpcutils.RequestUserIDFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid account delegation")
		}
		if verifier == nil {
			log.LogUnexpected(ctx, "verify account delegation", "verification unavailable")
			return nil, status.Error(codes.Unavailable, "account delegation unavailable")
		}

		claims, err := verifier.VerifySessionAccessToken(ctx, raw, accountDelegationAudience)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, status.FromContextError(err).Err()
		}
		if errors.Is(err, oidctoken.ErrInvalidToken) || errors.Is(err, oidctoken.ErrExpiredToken) {
			return nil, status.Error(codes.Unauthenticated, "invalid account delegation")
		}
		if err != nil {
			log.LogUnexpected(ctx, "verify account delegation", "verification unavailable")
			return nil, status.Error(codes.Unavailable, "account delegation unavailable")
		}
		if claims.UserID != userID {
			return nil, status.Error(codes.PermissionDenied, "account delegation denied")
		}

		md, _ := metadata.FromIncomingContext(ctx)
		clean := md.Copy()
		clean.Delete(grpcutils.AuthorizationMetadataKey)
		return handler(metadata.NewIncomingContext(ctx, clean), req)
	}
}

func accountBearer(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	values := md.Get(grpcutils.AuthorizationMetadataKey)
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}
