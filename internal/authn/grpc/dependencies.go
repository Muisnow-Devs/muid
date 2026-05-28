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

// HandlerDependencies houses all dependency injections for GRPCHandler.
// Per-method identity stores are now encapsulated inside IdentityManager and
// accessed via VerifiedStep.Identity.Store; they are no longer listed here.
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
