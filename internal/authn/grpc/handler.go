package authngrpc

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/uuid"
	pb "sanzi.io/muid/api/proto/authn/v1"
	basicpb "sanzi.io/muid/api/proto/authn/v1/basic"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/accesstoken"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/identity/policy"
	"sanzi.io/muid/internal/identity/resolver"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/internal/signature"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// GRPCHandler implements Authn's focused gRPC services.
type GRPCHandler struct {
	pb.UnimplementedAuthenticationFlowServiceServer
	pb.UnimplementedSessionServiceServer
	pb.UnimplementedLinkedIdentityServiceServer
	pb.UnimplementedSigningKeyServiceServer

	db              *authnent.Client
	transitionStore session.AuthTransitionStore
	pubSub          pubsub.PubSub
	secureLink      string
	maxAuthAttempts int64

	policy          policy.LinkPolicy
	resolver        resolver.UserResolver
	issuer          issuer.SessionIssuer
	identityManager *identity.IdentityManager

	accessTokens *accesstoken.Minter
	signing      signature.SignatureManager
}

// NewGRPCHandler returns a GRPCHandler wired from the provided dependencies.
func NewGRPCHandler(deps HandlerDependencies) *GRPCHandler {
	ma := int64(deps.MaxAuthAttempts)
	if ma < 1 {
		ma = 3
	}
	return &GRPCHandler{
		db:              deps.DB,
		transitionStore: deps.TransitionStore,
		pubSub:          deps.PubSub,
		secureLink:      deps.SecureLink,
		maxAuthAttempts: ma,
		policy:          deps.Policy,
		resolver:        deps.Resolver,
		issuer:          deps.Issuer,
		identityManager: deps.IdentityManager,
		accessTokens:    deps.AccessTokens,
		signing:         deps.SignatureManager,
	}
}

// continueAuthSuccess builds a successful ContinueLoginResponse.
func continueAuthSuccess(
	tid uuid.UUID,
	res *sessionpb.AuthenticatedResult,
) *pb.ContinueLoginResponse {
	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(res)

	out := &pb.ContinueLoginResponse{}
	out.SetTransitionId(tid.String())
	out.SetStatus(basicpb.AuthStatus_AUTH_STATUS_AUTHENTICATED)
	out.SetAuthSuccess(authOK)
	return out
}

// authFailureStatus builds a gRPC error for an application-level auth failure.
// The AuthFailure proto is attached as a typed error detail so clients can
// extract the structured AuthErrorCode via status.FromError(err).Details().
func authFailureStatus(grpcCode codes.Code, f *sessionpb.AuthFailure) error {
	st, detailErr := status.New(grpcCode, f.GetReason()).WithDetails(f)
	if detailErr != nil {
		// Fallback: should never happen for a well-formed proto message.
		return status.Error(grpcCode, f.GetReason())
	}
	return st.Err()
}

// newAuthFailureProto is the handler-layer convenience builder for AuthFailure.
// Each layer (method, handler) owns its own copy so neither depends on the other.
func newAuthFailureProto(code sessionpb.AuthErrorCode, reason string) *sessionpb.AuthFailure {
	f := &sessionpb.AuthFailure{}
	f.SetErrorCode(code)
	f.SetReason(reason)
	return f
}
