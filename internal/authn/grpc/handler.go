package authngrpc

import (
	"strings"

	"github.com/google/uuid"
	pb "sanzi.io/muid/api/proto/authn/v1"
	basicpb "sanzi.io/muid/api/proto/authn/v1/basic"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/identity/policy"
	"sanzi.io/muid/internal/identity/resolver"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// GRPCHandler implements the AuthnService gRPC server.
type GRPCHandler struct {
	pb.UnimplementedAuthnServiceServer

	db              *authnent.Client
	transitionStore session.AuthTransitionStore
	pubSub          pubsub.PubSub
	secureLink      string

	policy          policy.LinkPolicy
	resolver        resolver.UserResolver
	issuer          issuer.SessionIssuer
	identityManager *identity.IdentityManager
}

// NewGRPCHandler wires a GRPCHandler from the provided dependencies.
func NewGRPCHandler(deps HandlerDependencies) pb.AuthnServiceServer {
	return &GRPCHandler{
		db:              deps.DB,
		transitionStore: deps.TransitionStore,
		pubSub:          deps.PubSub,
		secureLink:      deps.SecureLink,
		policy:          deps.Policy,
		resolver:        deps.Resolver,
		issuer:          deps.Issuer,
		identityManager: deps.IdentityManager,
	}
}

func sessionTokenValue(tok *sessionpb.SessionToken) string {
	if tok == nil {
		return ""
	}
	return strings.TrimSpace(tok.GetValue())
}

func continueAuthSuccess(
	tid uuid.UUID,
	res *sessionpb.AuthenticatedResult,
) *pb.ContinueAuthSessionResponse {
	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(res)

	out := &pb.ContinueAuthSessionResponse{}
	out.SetTransitionId(tid.String())
	out.SetStatus(basicpb.AuthStatus_AUTH_STATUS_AUTHENTICATED)
	out.SetAuthSuccess(authOK)
	return out
}

func continueAuthFailure(tid uuid.UUID, reason, code string) *pb.ContinueAuthSessionResponse {
	fail := &sessionpb.AuthFailure{}
	fail.SetReason(reason)
	fail.SetErrorCode(code)

	out := &pb.ContinueAuthSessionResponse{}
	out.SetTransitionId(tid.String())
	out.SetStatus(basicpb.AuthStatus_AUTH_STATUS_FAILED)
	out.SetAuthFailure(fail)
	return out
}
