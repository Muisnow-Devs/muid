package authngrpc

import (
	"sanzi.io/muid/internal/authn/accesstoken"
	"sanzi.io/muid/internal/authn/account"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/identity/policy"
	"sanzi.io/muid/internal/identity/resolver"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/internal/signature"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// HandlerDependencies contains the dependencies for GRPCHandler.
type HandlerDependencies struct {
	AccountReader   account.Reader
	DB              *authnent.Client
	TransitionStore session.AuthTransitionStore
	PubSub          pubsub.PubSub
	SecureLink      string

	MaxAuthAttempts int

	Policy          policy.LinkPolicy
	Resolver        resolver.UserResolver
	Issuer          issuer.SessionIssuer
	IdentityManager *identity.IdentityManager

	// AccessTokens mints session access tokens; nil disables the feature.
	AccessTokens *accesstoken.Minter
	// SignatureManager serves the JWKS public keys; nil when no signing key
	// is configured (GetPublicKeys then answers Unavailable).
	SignatureManager signature.SignatureManager
}
