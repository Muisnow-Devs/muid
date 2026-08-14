package authngrpc

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/pkg/clientmeta"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

type transitionIDKey struct{}

// TransitionIDFromContext returns the transition ID stored by [AuthnRequestContextInterceptor]
// for [AuthenticationFlowService.ContinueLogin] calls.
func TransitionIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	if ctx == nil {
		return uuid.Nil, false
	}
	id, ok := ctx.Value(transitionIDKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// AuthnRequestContextInterceptor enriches the context for routes that need
// client metadata or transition ID parsing. Session token enrichment is handled
// separately by [grpcutils.SessionTokenInterceptor] and
// [AuthnSessionPrincipalInterceptor].
func AuthnRequestContextInterceptor() grpc.UnaryServerInterceptor {
	return grpcutils.UnaryRequestContextInterceptor(map[string]grpcutils.RequestContextFunc{
		pb.AuthenticationFlowService_StartLogin_FullMethodName:    enrichStartLogin,
		pb.AuthenticationFlowService_ContinueLogin_FullMethodName: enrichContinueLogin,
	})
}

func enrichStartLogin(ctx context.Context, _ string, req any) (context.Context, error) {
	if _, ok := req.(*pb.StartLoginRequest); !ok {
		log.LogUnexpected(
			ctx,
			"authn request context interceptor",
			"unexpected request type for StartLogin",
		)
		return ctx, status.Errorf(codes.Internal, "internal error")
	}
	return enrichClientMeta(ctx)
}

func enrichClientMeta(ctx context.Context) (context.Context, error) {
	ctx, err := clientmeta.EnrichFromIncomingMetadata(ctx)
	if err == nil {
		return ctx, nil
	}
	if errors.Is(err, clientmeta.ErrInvalidTimezone) {
		return ctx, status.Error(codes.InvalidArgument, err.Error())
	}
	return ctx, err
}

func enrichContinueLogin(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.ContinueLoginRequest)
	if !ok {
		log.LogUnexpected(
			ctx,
			"authn request context interceptor",
			"unexpected request type for ContinueLogin",
		)
		return ctx, status.Errorf(codes.Internal, "internal error")
	}

	tid, err := uuid.Parse(strings.TrimSpace(r.GetTransitionId()))
	if err != nil {
		return ctx, status.Error(codes.InvalidArgument, "invalid transition id")
	}
	ctx = log.WithAttrs(ctx, log.TransitionID(tid))
	return context.WithValue(ctx, transitionIDKey{}, tid), nil
}
