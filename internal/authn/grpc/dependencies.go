package authngrpc

import (
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/identity/policy"
	"sanzi.io/muid/internal/identity/resolver"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// HandlerDependencies contains the dependencies for GRPCHandler.
type HandlerDependencies struct {
	DB              *authnent.Client
	TransitionStore session.AuthTransitionStore
	PubSub          pubsub.PubSub
	SecureLink      string

	Policy          policy.LinkPolicy
	Resolver        resolver.UserResolver
	Issuer          issuer.SessionIssuer
	IdentityManager *identity.IdentityManager
}
