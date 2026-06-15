package app

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/httpx"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	"sanzi.io/muid/pkg/gateway/ratelimit"
	"sanzi.io/muid/pkg/gateway/risk"
	"sanzi.io/muid/pkg/log"
)

// requireAuth verifies a Bearer session token and authorizes the caller against
// the admin allowlist. The session JWT carries no admin role, so the allowlist
// is the gateway's authorization gate; an empty allowlist (debug only) permits
// any authenticated caller. The internal admin surface never permits anonymous
// access.
func requireAuth(verifier *jwtauth.Verifier, adminUserIDs []string) httpx.Middleware {
	admins := make(map[string]struct{}, len(adminUserIDs))
	for _, id := range adminUserIDs {
		if id = strings.TrimSpace(id); id != "" {
			admins[id] = struct{}{}
		}
	}
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
			if len(admins) > 0 {
				if _, ok := admins[claims.UserID.String()]; !ok {
					httpx.Error(w, http.StatusForbidden, "forbidden", "not an administrator")
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(jwtauth.WithClaims(r.Context(), claims)))
		})
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
