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
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/clientmeta"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

type (
	wireSessionKey  struct{}
	transitionIDKey struct{}
)

const (
	msgInvalidSessionToken = "invalid session token"
	msgMissingSessionToken = "missing session token"
)

// WireSessionFromContext returns a validated wire session token stored by [AuthnRequestContextInterceptor].
func WireSessionFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	wire, ok := ctx.Value(wireSessionKey{}).(string)
	return wire, ok && wire != ""
}

// TransitionIDFromContext returns the transition id for ContinueAuthSession when present.
func TransitionIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	if ctx == nil {
		return uuid.Nil, false
	}
	id, ok := ctx.Value(transitionIDKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// AuthnRequestContextInterceptor validates wire session tokens and attaches safe log attrs.
func AuthnRequestContextInterceptor() grpc.UnaryServerInterceptor {
	return grpcutils.UnaryRequestContextInterceptor(map[string]grpcutils.RequestContextFunc{
		pb.AuthnService_StartAuthSession_FullMethodName:          enrichStartAuthSession,
		pb.AuthnService_ContinueAuthSession_FullMethodName:       enrichContinueAuthSession,
		pb.AuthnService_GetAuthorizedSession_FullMethodName:      enrichRequiredWireSession,
		pb.AuthnService_GetAuthenticatedPrincipal_FullMethodName: enrichRequiredWireSession,
		pb.AuthnService_RevokeSession_FullMethodName:             enrichRequiredWireSession,
		pb.AuthnService_RevokeFederatedIdentity_FullMethodName:   enrichRequiredWireSession,
	})
}

func enrichStartAuthSession(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.StartAuthSessionRequest)
	if !ok {
		return ctx, status.Errorf(codes.Internal, "unsupported request type")
	}
	ctx, err := enrichClientMeta(ctx)
	if err != nil {
		return ctx, err
	}
	return enrichOptionalWireSession(ctx, r.GetSessionToken())
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

func enrichContinueAuthSession(ctx context.Context, _ string, req any) (context.Context, error) {
	r, ok := req.(*pb.ContinueAuthSessionRequest)
	if !ok {
		return ctx, status.Errorf(codes.Internal, "unsupported request type")
	}

	tid, err := uuid.Parse(strings.TrimSpace(r.GetTransitionId()))
	if err != nil {
		return ctx, status.Error(codes.InvalidArgument, "invalid transition id")
	}
	ctx = log.WithAttrs(ctx, log.TransitionID(tid))
	ctx = context.WithValue(ctx, transitionIDKey{}, tid)

	return enrichOptionalWireSession(ctx, r.GetSessionToken())
}

func enrichRequiredWireSession(ctx context.Context, _ string, req any) (context.Context, error) {
	switch r := req.(type) {
	case *pb.GetAuthorizedSessionRequest:
		return enrichRequiredWireSessionToken(ctx, r.GetSessionToken())
	case *pb.GetAuthenticatedPrincipalRequest:
		return enrichRequiredWireSessionToken(ctx, r.GetSessionToken())
	case *pb.RevokeSessionRequest:
		return enrichRequiredWireSessionToken(ctx, r.GetSessionToken())
	case *pb.RevokeFederatedIdentityRequest:
		return enrichRequiredWireSessionToken(ctx, r.GetSessionToken())
	default:
		return ctx, status.Errorf(codes.Internal, "unsupported request type")
	}
}

func enrichOptionalWireSession(
	ctx context.Context,
	tok *sessionpb.SessionToken,
) (context.Context, error) {
	wire := sessionTokenValue(tok)
	if wire == "" {
		return ctx, nil
	}
	_, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		return ctx, status.Error(codes.InvalidArgument, msgInvalidSessionToken)
	}
	return context.WithValue(ctx, wireSessionKey{}, wire), nil
}

func enrichRequiredWireSessionToken(
	ctx context.Context,
	tok *sessionpb.SessionToken,
) (context.Context, error) {
	wire := sessionTokenValue(tok)
	if wire == "" {
		return ctx, status.Error(codes.InvalidArgument, msgMissingSessionToken)
	}
	_, _, err := session.ParseWireSessionToken(wire)
	if err != nil {
		return ctx, status.Error(codes.InvalidArgument, msgInvalidSessionToken)
	}
	return context.WithValue(ctx, wireSessionKey{}, wire), nil
}

func requiredWireSession(ctx context.Context) (string, error) {
	wire, ok := WireSessionFromContext(ctx)
	if !ok {
		return "", status.Error(codes.InvalidArgument, msgMissingSessionToken)
	}
	return wire, nil
}

func optionalWireSession(ctx context.Context, tok *sessionpb.SessionToken) string {
	if wire, ok := WireSessionFromContext(ctx); ok {
		return wire
	}
	return sessionTokenValue(tok)
}

func transitionIDString(ctx context.Context, req *pb.ContinueAuthSessionRequest) string {
	if id, ok := TransitionIDFromContext(ctx); ok {
		return id.String()
	}
	return strings.TrimSpace(req.GetTransitionId())
}
