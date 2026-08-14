package app

import (
	"context"
	"time"

	"sanzi.io/muid/internal/authn/accesstoken"
	"sanzi.io/muid/internal/authn/account"
	authngrpc "sanzi.io/muid/internal/authn/grpc"
	"sanzi.io/muid/internal/authn/oidc"
	oidcpolicy "sanzi.io/muid/internal/authn/oidc/policy"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/identity/policy"
	"sanzi.io/muid/internal/identity/resolver"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/pkg/errutil"
)

// AuthnApp wires the authn gRPC server lifecycle.
type AuthnApp struct {
	server             *AuthnGRPC
	dependencyInjector *InfraDependencies
}

// NewAuthnApp returns an authn application wired from infra dependencies.
func NewAuthnApp(infra *InfraDependencies) (*AuthnApp, error) {
	pol := policy.NewEntLinkPolicy(infra.entClient)
	res := resolver.NewEntUserResolver(
		infra.entClient,
		infra.ProfileCli,
		infra.ProfileCallTimeoutSeconds,
	)
	iss := issuer.NewEntSessionIssuer(infra.entClient, infra.SessionCache)

	handler := authngrpc.NewGRPCHandler(authngrpc.HandlerDependencies{
		AccountReader:    account.NewManager(infra.entClient),
		DB:               infra.entClient,
		TransitionStore:  infra.TransitionStore,
		PubSub:           infra.PubSub,
		SecureLink:       infra.GlobalConfig.LoginAlertSecureLink,
		MaxAuthAttempts:  infra.GlobalConfig.MaxAuthAttempts,
		Policy:           pol,
		Resolver:         res,
		Issuer:           iss,
		IdentityManager:  infra.IdentityManager,
		AccessTokens:     newSessionAccessTokenMinter(infra),
		SignatureManager: infra.SignatureManager,
	})
	oidcProvider := newOIDCProvider(infra)
	service, err := NewAuthnGRPC(
		infra.GlobalConfig,
		handler,
		authngrpc.NewOIDCHandler(oidcProvider),
		authngrpc.NewOIDCAdminHandler(newOIDCAdmin(infra)),
		iss,
		newSessionAccessTokenVerifier(infra),
		infra.PlatformAuthz,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &AuthnApp{
		server:             service,
		dependencyInjector: infra,
	}, nil
}

func newSessionAccessTokenVerifier(infra *InfraDependencies) *oidctoken.Verifier {
	cfg := infra.GlobalConfig
	if !cfg.SessionAccessTokenEnabled() || infra.SignatureManager == nil {
		return nil
	}
	return oidctoken.NewVerifier(infra.SignatureManager, cfg.SessionAccessTokenIssuer)
}

// newOIDCProvider assembles the OIDC provider domain layer; nil when the OP
// surface is not configured (handlers then answer Unavailable). The
// SignatureManager alone is not enough: it is also wired when only session
// access tokens are enabled.
func newOIDCProvider(infra *InfraDependencies) *oidc.Provider {
	cfg := infra.GlobalConfig
	if !cfg.OIDCProviderEnabled() || infra.SignatureManager == nil {
		return nil
	}
	evaluator := oidcpolicy.NewEvaluator(
		oidcpolicy.LocalEnforcerAccess{Enforcer: infra.AuthzEnforcer},
		oidcpolicy.EntAllowlist{DB: infra.entClient},
	)
	return oidc.NewProvider(
		infra.entClient,
		infra.OIDCCodes,
		infra.OIDCPendings,
		infra.OIDCDevices,
		evaluator,
		oidctoken.NewSigner(infra.SignatureManager, cfg.OIDCIssuer),
		oidctoken.NewVerifier(infra.SignatureManager, cfg.OIDCIssuer),
		infra.ProfileCli,
		oidc.Config{
			Issuer:                cfg.OIDCIssuer,
			AccessTokenTTL:        time.Duration(cfg.OIDCAccessTokenTTLSeconds) * time.Second,
			DeviceVerificationURI: cfg.OIDCDeviceVerificationURI,
			DevicePollInterval:    time.Duration(cfg.OIDCDevicePollIntervalSeconds) * time.Second,
		},
	)
}

// newOIDCAdmin assembles the client-administration domain layer; nil when
// the OP surface is not configured.
func newOIDCAdmin(infra *InfraDependencies) *oidc.Admin {
	if !infra.GlobalConfig.OIDCProviderEnabled() || infra.SignatureManager == nil {
		return nil
	}
	return oidc.NewAdmin(
		infra.entClient,
		oidcpolicy.LocalEnforcerAccess{Enforcer: infra.AuthzEnforcer},
	)
}

// newSessionAccessTokenMinter assembles the session access token minter; nil
// when the feature is not configured (IssueAccessToken then answers
// Unavailable and login responses omit the access token).
func newSessionAccessTokenMinter(infra *InfraDependencies) *accesstoken.Minter {
	cfg := infra.GlobalConfig
	if !cfg.SessionAccessTokenEnabled() || infra.SignatureManager == nil {
		return nil
	}
	return accesstoken.NewMinter(
		oidctoken.NewSigner(infra.SignatureManager, cfg.SessionAccessTokenIssuer),
		infra.ProfileCli,
		infra.ProfileCallTimeoutSeconds,
		time.Duration(cfg.SessionAccessTokenTTLSeconds)*time.Second,
	)
}

func (app *AuthnApp) Start(ctx context.Context) error {
	if app.dependencyInjector.SignatureManager != nil {
		err := app.dependencyInjector.SignatureManager.Start(ctx)
		if err != nil {
			return err
		}
	}
	return app.server.Start(ctx)
}

func (app *AuthnApp) Stop() {
	app.server.Stop()
	errutil.Discard(app.dependencyInjector.Close())
}
