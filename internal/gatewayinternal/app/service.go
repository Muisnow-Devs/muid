package app

import (
	"net/http"

	"sanzi.io/muid/pkg/gateway/httpx"
	"sanzi.io/muid/pkg/gateway/risk"
)

// newHandler builds the internal gateway's routed handler. Health is exposed
// unauthenticated for liveness probes; every /admin route sits behind the
// auth → rate-limit → risk chain.
func newHandler(deps *InfraDependencies) http.Handler {
	cfg := deps.GlobalConfig
	admin := newAdminHandlers(deps)

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /admin/authz/casbin-rules", admin.listCasbinRules)
	adminMux.HandleFunc("POST /admin/authz/reload-policy", admin.reloadPolicy)
	adminMux.HandleFunc("GET /admin/oidc/clients", admin.listOIDCClients)

	limiter := newRateLimiter(deps)
	tracker := risk.NewTracker(deps.Redis, risk.TrackerConfig{})
	evaluator := risk.NewEvaluator(risk.Config{
		PoWThreshold:   cfg.RiskPoWThreshold,
		BlockThreshold: cfg.RiskBlockThreshold,
	})

	protected := httpx.Chain(adminMux,
		requireAuth(deps.Verifier, cfg.AdminUserIDs),
		rateLimit(limiter),
		riskCheck(tracker, evaluator, cfg.TrustForwardHeader, cfg.RealIPHeader),
	)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.Handle("/", protected)

	return httpx.Chain(root,
		httpx.TraceID,
		httpx.Logging,
		httpx.Recover,
		httpx.SecurityHeaders,
	)
}
