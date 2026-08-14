package app

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/httpx"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	"sanzi.io/muid/pkg/gateway/ratelimit"
	"sanzi.io/muid/pkg/gateway/risk"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

type platformPermissionChecker interface {
	CheckPermission(context.Context, uuid.UUID, string) (bool, error)
}

// requireAuth verifies a Bearer session token and attaches its user identity.
// Administrator authority is resolved live from Authz by requirePlatformPermission.
func requireAuth(verifier *jwtauth.Verifier) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := httpmeta.BearerToken(r.Header.Get("Authorization"))
			if raw == "" {
				httpx.Error(w, http.StatusUnauthorized, "unauthorized", "admin token required")
				return
			}
			claims, err := verifier.Verify(r.Context(), raw)
			if err != nil {
				if errors.Is(err, jwtauth.ErrExpiredToken) {
					httpx.Error(w, http.StatusUnauthorized, "token_expired", "session expired")
					return
				}
				httpx.Error(w, http.StatusUnauthorized, "invalid_token", "invalid admin token")
				return
			}
			next.ServeHTTP(w, r.WithContext(jwtauth.WithClaims(r.Context(), claims)))
		})
	}
}

// requirePlatformPermission checks the live Authz platform binding for the
// concrete route. Unknown admin routes fail closed until explicitly mapped.
func requirePlatformPermission(checker platformPermissionChecker) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permission, ok := adminRoutePermission(r.Method, r.URL.Path)
			if !ok {
				httpx.Error(w, http.StatusForbidden, "forbidden", "admin route is not permitted")
				return
			}
			claims, ok := jwtauth.ClaimsFromContext(r.Context())
			if !ok || claims.UserID == uuid.Nil {
				httpx.Error(w, http.StatusUnauthorized, "unauthorized", "admin token required")
				return
			}
			if checker == nil {
				httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "authorization unavailable")
				return
			}

			checkCtx := httpmeta.WithOutgoing(r.Context(), httpmeta.Fields{})
			allowed, err := checker.CheckPermission(checkCtx, claims.UserID, permission)
			if err != nil {
				log.LogUnexpected(r.Context(), "gateway-internal platform authorization", err.Error(), log.UserID(claims.UserID))
				httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "authorization unavailable")
				return
			}
			if !allowed {
				httpx.Error(w, http.StatusForbidden, "forbidden", "not an administrator")
				return
			}
			next.ServeHTTP(w, r.WithContext(checkCtx))
		})
	}
}

func adminRoutePermission(method, path string) (string, bool) {
	switch {
	case method == http.MethodGet && path == "/admin/authz/casbin-rules":
		return authzmodel.PlatformPermissionPolicyRead, true
	case method == http.MethodPost && path == "/admin/authz/reload-policy":
		return authzmodel.PlatformPermissionPolicyReload, true
	case method == http.MethodGet && path == "/admin/oidc/clients":
		return authzmodel.PlatformPermissionOIDCClientRead, true
	default:
		return "", false
	}
}

// rateLimit enforces a fixed-window quota keyed by the admin user id.
func rateLimit(limiter *ratelimit.Limiter) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identifier := "anon"
			if claims, ok := jwtauth.ClaimsFromContext(r.Context()); ok {
				identifier = "user:" + claims.UserID.String()
			}
			res, err := limiter.Allow(r.Context(), identifier)
			if err != nil {
				log.LogUnexpected(r.Context(), "gateway-internal rate limit", err.Error())
				httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "rate limiter unavailable")
				return
			}
			if !res.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())))
				httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// riskCheck scores the admin caller and blocks high-risk traffic. There is no
// CAPTCHA/PoW at the internal edge, so an elevated score short-circuits to 403.
func riskCheck(tracker *risk.Tracker, evaluator *risk.Evaluator, trustXFF bool, realIPHeader string) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			identifier := httpmeta.ClientIP(r, httpmeta.ClientIPConfig{TrustForwardHeader: trustXFF, RealIPHeader: realIPHeader})
			authenticated := false
			if claims, ok := jwtauth.ClaimsFromContext(ctx); ok {
				identifier = "user:" + claims.UserID.String()
				authenticated = true
			}

			requestRate, authFailures, err := tracker.Observe(ctx, identifier)
			if err != nil {
				log.LogUnexpected(ctx, "gateway-internal risk tracker", err.Error())
				requestRate, authFailures = 0, 0
			}
			decision, err := evaluator.Evaluate(ctx, risk.Signal{
				IP:            identifier,
				Authenticated: authenticated,
				RequestRate:   requestRate,
				AuthFailures:  authFailures,
				Headers:       r.Header,
			})
			if err != nil {
				log.LogUnexpected(ctx, "gateway-internal risk evaluate", err.Error())
				httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "risk evaluation unavailable")
				return
			}
			if decision.Action == risk.ActionBlock {
				log.Logger(ctx).Warn("gateway-internal blocked admin request", "id", identifier, "score", decision.Score, "reasons", decision.Reasons)
				httpx.Error(w, http.StatusForbidden, "forbidden", "request blocked by risk policy")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func newRateLimiter(deps *InfraDependencies) *ratelimit.Limiter {
	cfg := deps.GlobalConfig
	return ratelimit.New(deps.Redis, ratelimit.Config{
		Limit:  cfg.RateLimit,
		Window: time.Duration(cfg.RateLimitWindowSeconds) * time.Second,
		Prefix: "internal",
	})
}
