package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sanzi.io/muid/infra/geoip"
	"sanzi.io/muid/internal/gatewaypublic/reqctx"
	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/httpx"
	"sanzi.io/muid/pkg/gateway/pow"
	"sanzi.io/muid/pkg/gateway/ratelimit"
	"sanzi.io/muid/pkg/gateway/risk"
	"sanzi.io/muid/pkg/log"
)

// protector is the public gateway's abuse-protection middleware: it resolves
// the client IP + geo, enforces the rate limit, scores risk, and either allows,
// demands a proof-of-work solution, or blocks the request.
type protector struct {
	geo       geoip.Resolver
	limiter   *ratelimit.Limiter
	tracker   *risk.Tracker
	evaluator *risk.Evaluator
	pow          *pow.Manager
	trustXFF     bool
	realIPHeader string
}

func newProtector(deps *InfraDependencies, tracker *risk.Tracker) *protector {
	cfg := deps.GlobalConfig
	return &protector{
		geo: deps.Geo,
		limiter: ratelimit.New(deps.Redis, ratelimit.Config{
			Limit:  cfg.RateLimit,
			Window: time.Duration(cfg.RateLimitWindowSeconds) * time.Second,
			Prefix: "public",
		}),
		tracker: tracker,
		evaluator: risk.NewEvaluator(risk.Config{
			PoWThreshold:     cfg.RiskPoWThreshold,
			BlockThreshold:   cfg.RiskBlockThreshold,
			BlockedCountries: cfg.BlockedCountries,
		}),
		pow:          pow.New(deps.Redis, pow.Config{Difficulty: cfg.PoWDifficulty}),
		trustXFF:     cfg.TrustForwardHeader,
		realIPHeader: cfg.RealIPHeader,
	}
}

// Middleware implements the extract → rate-limit → risk pipeline.
func (p *protector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		clientIP := httpmeta.ClientIP(r, httpmeta.ClientIPConfig{TrustForwardHeader: p.trustXFF, RealIPHeader: p.realIPHeader})

		// Best-effort geo; failures degrade to "unresolved", never block here.
		geoInfo, err := p.geo.Resolve(clientIP)
		if err != nil {
			geoInfo = geoip.GeoInfo{IP: clientIP}
		}

		allow, err := p.limiter.Allow(ctx, clientIP)
		if err != nil {
			log.LogUnexpected(ctx, "gateway rate limit", err.Error())
			httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "rate limiter unavailable")
			return
		}
		if !allow.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(allow.RetryAfter.Seconds())))
			httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}

		requestRate, authFailures, err := p.tracker.Observe(ctx, clientIP)
		if err != nil {
			log.LogUnexpected(ctx, "gateway risk tracker", err.Error())
			requestRate, authFailures = 0, 0
		}

		decision, err := p.evaluator.Evaluate(ctx, risk.Signal{
			IP:           clientIP,
			RequestRate:  requestRate,
			AuthFailures: authFailures,
			Headers:      r.Header,
			Geo: risk.Geo{
				CountryCode: geoInfo.CountryCode,
				Resolved:    geoInfo.Resolved,
			},
		})
		if err != nil {
			log.LogUnexpected(ctx, "gateway risk evaluate", err.Error())
			httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "risk evaluation unavailable")
			return
		}

		switch decision.Action {
		case risk.ActionBlock:
			log.Logger(ctx).Warn("gateway blocked request", "ip", clientIP, "score", decision.Score, "reasons", decision.Reasons)
			httpx.Error(w, http.StatusForbidden, "forbidden", "request blocked by risk policy")
			return
		case risk.ActionRequirePoW:
			if !p.satisfiedPoW(ctx, r) {
				p.challenge(ctx, w)
				return
			}
		case risk.ActionAllow:
		}

		ctx = reqctx.WithFacts(ctx, reqctx.Facts{ClientIP: clientIP, GeoCountry: geoInfo.CountryCode})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// satisfiedPoW returns true when the request carries a valid, single-use PoW
// solution in the X-Pow-Id / X-Pow-Solution headers.
func (p *protector) satisfiedPoW(ctx context.Context, r *http.Request) bool {
	id := strings.TrimSpace(r.Header.Get("X-Pow-Id"))
	solution := strings.TrimSpace(r.Header.Get("X-Pow-Solution"))
	if id == "" || solution == "" {
		return false
	}
	return p.pow.Verify(ctx, id, solution) == nil
}

// challenge issues a fresh PoW challenge with HTTP 401.
func (p *protector) challenge(ctx context.Context, w http.ResponseWriter) {
	ch, err := p.pow.Issue(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "gateway pow issue", err.Error())
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "challenge unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":            "pow_required",
		"pow_challenge_id": ch.ID,
		"pow_seed":         ch.Seed,
		"pow_difficulty":   ch.Difficulty,
	})
}
