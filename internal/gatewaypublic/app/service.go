package app

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"

	"sanzi.io/muid/internal/gatewaypublic/graph"
	"sanzi.io/muid/internal/gatewaypublic/graph/generated"
	"sanzi.io/muid/internal/gatewaypublic/graph/loader"
	"sanzi.io/muid/internal/gatewaypublic/graph/persisted"
	"sanzi.io/muid/internal/gatewaypublic/reqctx"
	"sanzi.io/muid/pkg/gateway/csrf"
	"sanzi.io/muid/pkg/gateway/httpx"
	"sanzi.io/muid/pkg/gateway/risk"
	"sanzi.io/muid/pkg/log"
)

// newHandler builds the public gateway's routed handler with the full
// middleware chain applied.
func newHandler(deps *InfraDependencies) http.Handler {
	cfg := deps.GlobalConfig
	oidc := newOIDCHandlers(deps)

	// One risk tracker is shared: the protector reads request-rate/failure
	// counts from it, and the GraphQL login resolver writes auth failures to it.
	tracker := risk.NewTracker(deps.Redis, risk.TrackerConfig{})
	protect := newProtector(deps, tracker)

	resolver := buildResolver(deps, tracker)

	// App routes sit behind the abuse-protection middleware (rate-limit + risk +
	// geo + IP extraction).
	appMux := http.NewServeMux()

	// App-facing GraphQL (auth flows + session lifecycle + authz/profile BFF).
	// Mutations are state-changing, so the endpoint is CSRF-protected when CSRF is
	// enabled. graphqlContext exposes the request/response to resolvers (for the
	// httpOnly cookies) and injects the per-request profile loader.
	gql := newGraphQLServer(deps, resolver)
	appMux.Handle("/graphql", graphqlContext(resolver, csrfProtect(deps.CSRF)(gql)))

	// OIDC discovery + JWKS (read-only, public).
	appMux.HandleFunc("GET /.well-known/openid-configuration", oidc.discovery)
	appMux.HandleFunc("GET /.well-known/jwks.json", oidc.jwks)

	// OIDC token + userinfo.
	appMux.HandleFunc("POST /oidc/token", oidc.token)
	appMux.HandleFunc("GET /oidc/userinfo", oidc.userinfo)
	appMux.HandleFunc("POST /oidc/userinfo", oidc.userinfo)

	// Security capability endpoints.
	if deps.CSRF != nil {
		appMux.HandleFunc("GET /security/csrf", csrfTokenHandler(deps.CSRF))
	}

	// Dedicated access-token endpoint: a subdomain app can proactively mint a
	// fresh access token from its session cookie. The gateway sets the
	// subdomain-scoped access-token cookie; the response carries no body.
	//
	// It is deliberately NOT CSRF-protected (it is meant to be called cross-
	// subdomain), so it is guarded by a server-side Origin allowlist instead. The
	// only side effect is refreshing the caller's own access-token cookie.
	appMux.Handle("POST /security/access-token",
		requireAllowedOrigin(cfg.CORSAllowedOrigins)(graphqlContext(resolver, accessTokenHandler(resolver))))

	// Health is liveness-only and must not depend on Redis/risk, so it is served
	// outside the protector chain.
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.Handle("/", httpx.Budget(httpx.BudgetConfig{
		RequestTimeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
		MaxConcurrent:  httpx.DefaultMaxConcurrentRequests,
	})(protect.Middleware(appMux)))

	// Cheap, always-on middleware wrap every route including health.
	middlewares := []httpx.Middleware{
		httpx.TraceID,
		httpx.Logging,
		httpx.Recover,
		httpx.SecurityHeaders,
	}
	if len(cfg.CORSAllowedOrigins) > 0 {
		middlewares = append(middlewares, httpx.CORS(httpx.CORSConfig{
			AllowedOrigins:   cfg.CORSAllowedOrigins,
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-CSRF-Token"},
			AllowCredentials: true,
		}))
	}
	return httpx.Chain(root, middlewares...)
}

// buildResolver wires the GraphQL root resolver with the authn/authz/profile
// clients, the local access-token verifier, the risk auth-failure recorder, and
// the cookie configuration.
func buildResolver(deps *InfraDependencies, tracker *risk.Tracker) *graph.Resolver {
	cfg := deps.GlobalConfig
	return &graph.Resolver{
		AuthFlow:       deps.AuthFlowClient,
		Session:        deps.SessionClient,
		LinkedIdentity: deps.LinkedIdentityClient,
		AuthzUser:      deps.AuthzUserClient,
		AuthzOrg:       deps.AuthzOrgClient,
		Profile:        deps.ProfileClient,
		OrgProfile:     deps.OrgProfileClient,
		Verifier:       deps.Verifier,
		Turnstile:      deps.Turnstile,
		Failures:       tracker,
		SessionCookieCfg: graph.SessionCookie{
			Name:     cfg.SessionCookieName,
			Secure:   cfg.SessionCookieSecure,
			SameSite: parseSameSite(cfg.SessionCookieSameSite),
		},
		AccessCookieCfg: graph.AccessTokenCookie{
			Name:     cfg.AccessTokenCookieName,
			Domain:   cfg.AccessTokenCookieDomain,
			Secure:   cfg.SessionCookieSecure,
			SameSite: parseSameSite(cfg.SessionCookieSameSite),
		},
	}
}

// newGraphQLServer builds the gqlgen server over the predefined public schema.
// Outside debug mode the trusted-documents allowlist limits clients to
// pre-registered operations and introspection stays off, so the schema is
// opaque to untrusted clients. Debug mode allows ad-hoc operations +
// introspection for local development.
func newGraphQLServer(deps *InfraDependencies, resolver *graph.Resolver) *handler.Server {
	cfg := deps.GlobalConfig
	es := generated.NewExecutableSchema(generated.Config{Resolvers: resolver})
	srv := handler.New(es)
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.POST{})
	srv.Use(extension.FixedComplexityLimit(100))
	srv.Use(persisted.New(deps.PersistedOps, cfg.Debug))
	if cfg.Debug {
		srv.Use(extension.Introspection{})
	}
	return srv
}

// graphqlContext exposes the live request/response to resolvers (so they can
// read and write the httpOnly session/access-token cookies) and injects a
// per-request profile loader so member listings dedupe GetProfile fan-out.
func graphqlContext(resolver *graph.Resolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := reqctx.WithHTTP(r.Context(), w, r)
		ctx = loader.WithContext(ctx, resolver.NewProfileLoader())
		ctx = graph.WithCaller(ctx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// accessTokenHandler mints a fresh access token from the caller's session cookie
// and sets the subdomain-scoped access-token cookie. The response is status-code
// only: the JWT lives in the httpOnly cookie and nothing is returned in the body.
func accessTokenHandler(resolver *graph.Resolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := resolver.MintAccessToken(r.Context()); err != nil {
			if errors.Is(err, graph.ErrNoSessionCookie) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// MintAccessToken has set the access-token cookie; return only a status.
		w.WriteHeader(http.StatusNoContent)
	}
}

// requireAllowedOrigin rejects cross-origin requests whose Origin is not in the
// allowlist. Used for the CSRF-exempt access-token endpoint. When no origins are
// configured (CORS disabled, e.g. local dev) the check is a no-op.
func requireAllowedOrigin(allowed []string) httpx.Middleware {
	set := make(map[string]struct{}, len(allowed))
	wildcard := false
	for _, o := range allowed {
		if o == "*" {
			wildcard = true
		}
		set[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// With an allowlist configured (production), the Origin must be
			// present and allowed — a missing Origin is rejected too. With no
			// allowlist (debug) the check is a no-op.
			if len(set) > 0 && !wildcard {
				origin := r.Header.Get("Origin")
				if origin == "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if _, ok := set[origin]; !ok {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// parseSameSite maps a config string onto http.SameSite, defaulting to Lax.
func parseSameSite(v string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// csrfProtect validates the X-CSRF-Token header on unsafe requests when CSRF is
// enabled. A nil manager disables enforcement (e.g. local dev without a secret).
func csrfProtect(manager *csrf.Manager) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if manager != nil && r.Method != http.MethodGet && r.Method != http.MethodOptions {
				if err := manager.Validate(r.Header.Get("X-CSRF-Token")); err != nil {
					httpx.Error(w, http.StatusForbidden, "csrf_invalid", "missing or invalid CSRF token")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// csrfTokenHandler issues a fresh CSRF token.
func csrfTokenHandler(manager *csrf.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := manager.Generate()
		if err != nil {
			log.LogUnexpected(r.Context(), "gateway csrf generate", err.Error())
			httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "csrf unavailable")
			return
		}
		httpx.JSON(w, r, http.StatusOK, map[string]string{"csrf_token": token})
	}
}
